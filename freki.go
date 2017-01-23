package freki

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/bpf"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kung-foo/freki/netfilter"
	"github.com/pkg/errors"
)

const table = "raw"

var chains = []string{"PREROUTING", "OUTPUT"}

func genRuleSpec(chain, iface, protocol, queuespec string) []string {
	spec := "-p,%s,-j,NFQUEUE,--queue-num,%s"
	if chain == "PREROUTING" {
		spec = "-i,%s," + spec
	}
	if chain == "OUTPUT" {
		spec = "-o,%s," + spec
	}
	return strings.Split(fmt.Sprintf(spec, iface, protocol, queuespec), ",")
}

type iptrule struct {
	table    string
	chain    string
	rulespec []string
}

func (r *iptrule) Append(ipt *iptables.IPTables) error {
	return ipt.AppendUnique(r.table, r.chain, r.rulespec...)
}

func (r *iptrule) Delete(ipt *iptables.IPTables) error {
	return ipt.Delete(r.table, r.chain, r.rulespec...)
}

type Processor struct {
	log              Logger
	rules            []*Rule
	ipt              *iptables.IPTables
	iptRules         []iptrule
	nfq              *netfilter.Queue
	cleanupOnce      sync.Once
	Connections      *connTable
	packetsProcessed uint64
	shutdown         chan struct{}
	publicAddrs      []net.IP
	iface            *pcap.Handle
	servers          map[string]Server
}

func New(ifaceName string, rules []*Rule, logger Logger) (*Processor, error) {
	iface, err := pcap.OpenLive(ifaceName, 1, false, time.Second)

	if err != nil {
		return nil, err
	}

	for idx, rule := range rules {
		err = initRule(idx, rule, iface)
		if err != nil {
			return nil, errors.Wrap(err, rule.String())
		}
	}

	nonLoopbackAddrs, err := getNonLoopbackIPs(ifaceName, logger)
	if err != nil {
		return nil, err
	}

	processor := &Processor{
		rules:       rules,
		log:         logger,
		iptRules:    make([]iptrule, 0),
		Connections: newConnTable(logger),
		shutdown:    make(chan struct{}),
		publicAddrs: nonLoopbackAddrs,
		iface:       iface,
		servers:     make(map[string]Server, 0),
	}

	// TODO: customize protocols

	for _, chain := range chains {
		r := iptrule{
			table:    table,
			chain:    chain,
			rulespec: genRuleSpec(chain, ifaceName, "tcp", "0"),
		}
		processor.iptRules = append(processor.iptRules, r)
	}

	return processor, nil
}

func (p *Processor) AddServer(s Server) {
	p.servers[s.Type()] = s
}

func (p *Processor) initIPTables() (err error) {
	for _, rule := range p.iptRules {
		err = rule.Append(p.ipt)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("%+v", rule))
		}
	}
	return
}

func (p *Processor) resetIPTables() (err error) {
	for _, rule := range p.iptRules {
		err = rule.Delete(p.ipt)
		if err != nil {
			p.log.Errorf("[freki   ] error deleting: %+v", rule)
		}
	}
	return
}

func (p *Processor) Init() (err error) {
	for _, rule := range p.rules {
		if rule.ruleType == ProxyTCP {
			if rule.targetURL.Scheme == "docker" {
				p.log.Debugf("[freki   ] Creating Docker client with version: %v", client.DefaultVersion)
				var cli *client.Client
				cli, err = client.NewEnvClient()
				if err != nil {
					return err
				}

				var containers []types.Container
				containers, err = cli.ContainerList(context.Background(), types.ContainerListOptions{})
				if err != nil {
					return err
				}

				found := false
				for _, container := range containers {
					name := container.Names[0][1:]
					if name == rule.host {
						// TODO: find correct network
						addr := container.NetworkSettings.Networks["bridge"].IPAddress
						p.log.Debugf("[freki   ] mapping docker://%s:%d to tcp://%s:%d", rule.host, rule.port, addr, rule.port)
						rule.targetURL.Host = fmt.Sprintf("tcp://%s:%d", addr, rule.port)
						rule.host = addr
						found = true
					}
				}

				if !found {
					return fmt.Errorf("unabled to find a container named: %s", rule.host)
				}
			}
		}
	}

	p.ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return
	}

	// quick permissions test
	_, err = p.ipt.List(table, chains[0])
	if err != nil {
		return
	}

	// TODO: check for conflicting rules
	err = p.initIPTables()
	if err != nil {
		return
	}

	for _, chain := range chains {
		filters, _ := p.ipt.List(table, chain)
		p.log.Debugf("[freki   ] %s %s %+v", table, chain, filters)
	}

	// TODO: set sane defaults
	p.nfq, err = netfilter.New(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)

	if err != nil {
		return
	}

	for _, server := range p.servers {
		go func(s Server) {
			p.log.Infof("[freki   ] starting %s on %d", s.Type(), s.Port())
			err := s.Start(p)
			if err != nil {
				p.log.Errorf("[freki   ] %v", err)
			}
		}(server)
	}

	return
}

func (p *Processor) PacketsProcessed() uint64 {
	return atomic.LoadUint64(&p.packetsProcessed)
}

func (p *Processor) Shutdown() (err error) {
	p.cleanupOnce.Do(func() {
		close(p.shutdown)
		// TODO: how to drain?
		err = p.cleanup()
	})
	return
}

func (p *Processor) cleanup() (err error) {
	p.log.Debug("[freki   ] Processor:cleanup()")

	p.resetIPTables()

	if p.nfq != nil {
		p.nfq.Close()
	}

	for _, chain := range chains {
		filters, _ := p.ipt.List(table, chain)
		p.log.Debugf("[freki   ] %s %s %+v", table, chain, filters)
	}

	if p.iface != nil {
		// TODO: does this really need to stay open the whole time?
		p.iface.Close()
	}

	for _, server := range p.servers {
		err = server.Shutdown()
		if err != nil {
			p.log.Errorf("[freki   ] %v", err)
			err = nil
		}
	}

	return
}

func (p *Processor) Start() (err error) {
	p.log.Infof("[freki   ] starting freki on %v", p.publicAddrs)

	go func() {
		ticker := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-ticker.C:
				p.Connections.FlushOlderThan(time.Second * 60)
			case <-p.shutdown:
				ticker.Stop()
				return
			}
		}
	}()

	// TODO: discover how "Run" returns
	go p.nfq.Run()

	return p.loop()
}

func (p *Processor) loop() (err error) {
	for {
		select {
		case raw := <-p.nfq.Packets():
			err = p.onPacket(raw)
			if err != nil {
				return
			}
		case <-p.shutdown:
			return
		}
	}
}

func (p *Processor) isIPNonLoopback(ip *net.IP) bool {
	for _, addr := range p.publicAddrs {
		if ip.Equal(addr) {
			return true
		}
	}
	return false
}

func (p *Processor) mangle(
	rawPacket *netfilter.RawPacket,
	packet gopacket.Packet,
	ip *layers.IPv4,
	tcp *layers.TCP,
	body *gopacket.Payload) error {

	var err error
	var buffer gopacket.SerializeBuffer

	if p.isIPNonLoopback(&ip.SrcIP) {
		// packets back to client
		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Dst(), tcp.TransportFlow().Dst())
		md := p.Connections.GetByFlow(ck)
		if md == nil {
			// not tracking
			goto accept
		}

		switch md.Rule.ruleType {
		case Rewrite, LogTCP, LogHTTP, ProxyTCP:
			tcp.SrcPort = layers.TCPPort(md.TargetPort)
			goto modified
		case Drop:
			goto drop
		case PassThrough:
			goto accept
		default:
			p.log.Errorf("[freki   ] rule not implmented: %+v", md.Rule)
		}
	} else {
		// packets to honeypots
		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
		md := p.Connections.GetByFlow(ck)
		if md == nil {
			// not tracking
			goto accept
		}

		var s Server
		var ok bool

		switch md.Rule.ruleType {
		case Rewrite:
			tcp.DstPort = layers.TCPPort(md.Rule.port)
			goto modified
		case LogTCP:
			// TODO: optimize?
			if s, ok = p.servers["log.tcp"]; !ok {
				return fmt.Errorf("No TCPLogger installed")
			}
			tcp.DstPort = layers.TCPPort(s.Port())
			goto modified
		case LogHTTP:
			// TODO: optimize?
			if s, ok = p.servers["log.http"]; !ok {
				return fmt.Errorf("No HTTPLogger installed")
			}
			tcp.DstPort = layers.TCPPort(s.Port())
			goto modified

		case ProxyTCP:
			// TODO: optimize?
			if s, ok = p.servers["log.tcp"]; !ok {
				return fmt.Errorf("No TCPPLogger installed")
			}
			tcp.DstPort = layers.TCPPort(s.Port())
			goto modified
		case Drop:
			goto drop
		case PassThrough:
			goto accept
		default:
			p.log.Errorf("[freki   ] rule not implmented: %+v", md.Rule)
		}
	}

	// default
	goto accept

modified:
	tcp.SetNetworkLayerForChecksum(ip)
	buffer = gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, body,
	)
	if err != nil {
		// TODO: should return a verdict?
		return err
	}

	return p.nfq.SetVerdictModifed(rawPacket, buffer.Bytes(), netfilter.NF_ACCEPT)
accept:
	return p.nfq.SetVerdict(rawPacket, netfilter.NF_ACCEPT)
drop:
	return p.nfq.SetVerdict(rawPacket, netfilter.NF_DROP)
}

var ethHdr = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,
}

func (p *Processor) onPacket(rawPacket *netfilter.RawPacket) (err error) {
	// TODO: remove defer
	defer func() {
		atomic.AddUint64(&p.packetsProcessed, 1)
	}()

	// OK, so this mess is because I want to use libpcap's BPF compiler which
	// emits instructions that expect an etherneet header. But, NFQUEUE only
	// emits IP and down. So I need to append a fake ethernet header. Ideally
	// I would have a BPF progam that could operate on the IP packet itself.
	buffer := append(ethHdr, rawPacket.Data...)

	// TODO: set DecodeOptions
	packet := gopacket.NewPacket(
		buffer,
		layers.LayerTypeEthernet,
		gopacket.DecodeOptions{Lazy: false, NoCopy: true},
	)

	// spew.Dump(packet)

	var (
		eth  layers.Ethernet
		ip   layers.IPv4
		tcp  layers.TCP
		udp  layers.UDP
		icmp layers.ICMPv4
		body gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&body)

	var foundLayerTypes []gopacket.LayerType
	err = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

	if err != nil {
		p.log.Errorf("[freki   ] %v %v", err, foundLayerTypes)
		goto accept
	}

	for _, layer := range foundLayerTypes {
		switch layer {
		case layers.LayerTypeTCP:
			// TODO: validate logic
			if tcp.SYN && !tcp.ACK {
				var rule *Rule
				srcIP := ip.NetworkFlow().Src()
				srcPort := tcp.TransportFlow().Src()
				p.log.Debugf("[freki   ] new connection %s:%s->%d", srcIP.String(), srcPort.String(), tcp.DstPort)
				rule, err = p.applyRules(packet)

				if err != nil {
					p.log.Errorf("[freki   ] %v", err)
					goto accept
				}

				if rule == nil {
					// TODO: is this the correct default?
					goto accept
				}

				// FYI: when i don't respond to a SYN, then a duplicate SYN is sent
				ck := NewConnKeyByEndpoints(srcIP, srcPort)
				p.Connections.Register(ck, rule, srcIP.String(), srcPort.String(), tcp.DstPort)
			}

			err = p.mangle(rawPacket, packet, &ip, &tcp, &body)
			return
		}
	}

accept:
	return p.nfq.SetVerdict(rawPacket, netfilter.NF_ACCEPT)
}

func (p *Processor) applyRules(packet gopacket.Packet) (*Rule, error) {
	/*
		if len(p.rules) == 0 {
			return nil, fmt.Errorf("no rules found")
		}
	*/

	for _, rule := range p.rules {
		if rule.matcher != nil {
			v, err := rule.matcher.Run(packet.Data())
			if err != nil {
				return nil, err
			}
			if v == 1 {
				return rule, nil
			}
		}
	}

	return nil, nil
}

func getNonLoopbackIPs(ifaceName string, logger Logger) ([]net.IP, error) {
	nonLoopback := []net.IP{}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nonLoopback, errors.Wrap(err, "pcap.FindAllDevs()")
	}

	for _, iface := range ifs {
		if strings.EqualFold(iface.Name, ifaceName) {
			for _, addr := range iface.Addresses {
				logger.Debugf("[freki   ] device: %s, addr: %s, isLoopback: %v, isIPv4: %v", ifaceName, addr.IP.String(), addr.IP.IsLoopback(), addr.IP.To4() != nil)
				if !addr.IP.IsLoopback() && addr.IP.To4() != nil {
					nonLoopback = append(nonLoopback, addr.IP)
				}
			}
		}
	}

	if len(nonLoopback) == 0 {
		return nonLoopback, fmt.Errorf("unable to find any non-loopback addresses for: %s", ifaceName)
	}

	return nonLoopback, nil
}

func pcapBPFToXNetBPF(pcapbpf []pcap.BPFInstruction) *bpf.VM {
	raw := make([]bpf.RawInstruction, len(pcapbpf))

	for i, ins := range pcapbpf {
		raw[i] = bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
	}

	filter, _ := bpf.Disassemble(raw)

	vm, err := bpf.NewVM(filter)

	if err != nil {
		// TODO: return error
		println(err)
		// p.log.Error(err)
	}

	return vm
}
