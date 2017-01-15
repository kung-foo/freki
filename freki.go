package freki

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/bpf"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kung-foo/freki/netfilter"
)

const table = "raw"

var chains = []string{"PREROUTING", "OUTPUT"}

func genRule(protocol, queuespec string) []string {
	return strings.Split(fmt.Sprintf("-p,%s,-j,NFQUEUE,--queue-num,%s", protocol, queuespec), ",")
}

var processor *Processor

type Processor struct {
	log              Logger
	rules            []*Rule
	ipt              *iptables.IPTables
	iptRules         [][]string
	nfq              *netfilter.Queue
	cleanupOnce      sync.Once
	Connections      *connTable
	packetsProcessed uint64
	shutdown         chan struct{}
	publicAddr       net.IP
}

func New(rules []*Rule, logger Logger) *Processor {
	processor = &Processor{
		rules:       rules,
		log:         logger,
		iptRules:    make([][]string, 0),
		Connections: newConnTable(),
		shutdown:    make(chan struct{}),
		publicAddr:  net.ParseIP("192.168.200.1"), //getLocalIP(),
	}

	// TODO: customize protocols
	processor.iptRules = append(processor.iptRules,
		genRule("tcp", "0"),
		// genRule("udp", "0"),
		// genRule("icmp", "0"),
	)

	return processor
}

func (p *Processor) initIPTables() (err error) {
	for _, rule := range p.iptRules {
		for _, chain := range chains {
			err = p.ipt.AppendUnique(table, chain, rule...)
			if err != nil {
				return
			}
		}
	}
	return
}

func (p *Processor) resetIPTables() (err error) {
	for _, rule := range p.iptRules {
		for _, chain := range chains {
			err = p.ipt.Delete(table, chain, rule...)
			if err != nil {
				p.log.Errorf("error deleting \"%s %s\": %v", table, chain, err)
			}
		}
	}
	return
}

func (p *Processor) Init() (err error) {
	p.ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return
	}

	_, err = p.ipt.List("filter", "INPUT")
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
		p.log.Debugf("%s %s %+v", table, chain, filters)
	}

	// TODO: set sane defaults
	p.nfq, err = netfilter.New(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)

	if err != nil {
		return
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
	p.log.Debug("Processor:cleanup()")

	p.resetIPTables()

	if p.nfq != nil {
		p.nfq.Close()
	}

	for _, chain := range chains {
		filters, _ := p.ipt.List(table, chain)
		p.log.Debugf("%s %s %+v", table, chain, filters)
	}
	return
}

func (p *Processor) Start() (err error) {
	p.log.Infof("starting freki on %s", p.publicAddr)

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

var localhost = net.ParseIP("127.0.0.1")

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

func (p *Processor) mangle(
	rawPacket *netfilter.RawPacket,
	packet gopacket.Packet,
	ip *layers.IPv4,
	tcp *layers.TCP,
	body *gopacket.Payload) error {

	var err error
	var buffer gopacket.SerializeBuffer

	if ip.SrcIP.Equal(p.publicAddr) {
		// packets back to client
		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Dst(), tcp.TransportFlow().Dst())
		md := p.Connections.GetByFlow(ck)
		if md == nil {
			// not tracking
			goto accept
		}

		switch md.Rule.ruleType {
		case Rewrite:
			tcp.SrcPort = layers.TCPPort(md.TargetPort)
			goto modified
		case Drop:
			goto drop
		case PassThrough:
			goto accept
		default:
			p.log.Errorf("rule not implmented: %+v", md.Rule)
		}
	} else {
		// packets to honeypots
		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
		md := p.Connections.GetByFlow(ck)
		if md == nil {
			// not tracking
			goto accept
		}

		switch md.Rule.ruleType {
		case Rewrite:
			tcp.DstPort = layers.TCPPort(md.Rule.port)
			goto modified
		case Drop:
			goto drop
		case PassThrough:
			goto accept
		default:
			p.log.Errorf("rule not implmented: %+v", md.Rule)
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

/*
func (p *Processor) hijackTCP(payload *nfqueue.Payload, packet gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP, body *gopacket.Payload) (err error) {
	if ip.SrcIP.Equal(p.publicAddr) {
		// packets back to client
		if tcp.SrcPort != layers.TCPPort(p.portRules.HijackTCPServerPort) {
			payload.SetVerdict(nfqueue.NF_ACCEPT)
			return
		}

		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Dst(), tcp.TransportFlow().Dst())
		md := p.Connections.GetByFlow(ck)

		if md == nil {
			// not tracking
			payload.SetVerdict(nfqueue.NF_ACCEPT)
			return
		}
		tcp.SrcPort = md.TargetPort
	} else {
		// handling packets
		if rule, ok := p.portRules.Ports[int(tcp.DstPort)]; ok {

			switch rule.Type {
			case "ignore":
				payload.SetVerdict(nfqueue.NF_ACCEPT)
				return
			case "hijack":
				tcp.DstPort = layers.TCPPort(p.portRules.HijackTCPServerPort)
			default:
				// TODO: Configure behaviour
				// payload.SetVerdict(nfqueue.NF_ACCEPT); return
				// payload.SetVerdict(nfqueue.NF_DROP); return
			}

			ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
			md := p.Connections.GetByFlow(ck)

			if md == nil {
				// not tracking
				payload.SetVerdict(nfqueue.NF_ACCEPT)
				return
			}
		}
	}

	tcp.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, body,
	)
	if err != nil {
		return err
	}

	err = payload.SetVerdictModified(nfqueue.NF_ACCEPT, buffer.Bytes())
	if err != nil {
		return err
	}

	return
}
*/
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
		p.log.Error(err, foundLayerTypes)
		goto accept
	}

	for _, layer := range foundLayerTypes {
		switch layer {
		case layers.LayerTypeTCP:
			// TODO: validate logic
			if tcp.SYN && !tcp.ACK {
				var rule *Rule
				rule, err = p.applyRules(packet)

				if err != nil {
					p.log.Error(err)
					goto accept
				}

				if rule == nil {
					// TODO: is this the correct default?
					goto accept
				}

				// FYI: when i don't respond to a SYN, then a duplicate SYN is sent
				ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
				p.Connections.Register(ck, rule, tcp.DstPort)
			}

			err = p.mangle(rawPacket, packet, &ip, &tcp, &body)

			if err != nil {
				p.log.Error(err)
			}

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

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}
	return nil
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
