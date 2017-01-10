package freki

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/bpf"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kung-foo/freki/netfilter"
	"github.com/kung-foo/nfqueue-go/nfqueue"
)

const table = "raw"

var chains = []string{"PREROUTING", "OUTPUT"}

func genRule(protocol, queuespec string) []string {
	return strings.Split(fmt.Sprintf("-p,%s,-j,NFQUEUE,--queue-num,%s", protocol, queuespec), ",")
}

var processor *Processor

type Processor struct {
	log              Logger
	ipt              *iptables.IPTables
	rules            [][]string
	nfq              *nfqueue.Queue
	cleanupOnce      sync.Once
	Connections      *connTable
	packetsProcessed uint64
	stop             chan struct{}
	publicAddr       net.IP
}

func New(logger Logger) *Processor {
	processor = &Processor{
		log:         logger,
		rules:       make([][]string, 0),
		Connections: newConnTable(),
		stop:        make(chan struct{}),
		publicAddr:  getLocalIP(),
	}

	// TODO: customize protocols
	processor.rules = append(processor.rules,
		genRule("tcp", "0"),
		// genRule("udp", "0"),
		// genRule("icmp", "0"),
	)

	return processor
}

func (p *Processor) initIPTables() (err error) {
	for _, rule := range p.rules {
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
	for _, rule := range p.rules {
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

	// DEMO!!!
	if true {
		nfq2, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
		if err != nil {
			p.log.Error(err)
		}

		go func() {
			for p := range nfq2.Packets() {
				nfq2.SetVerdict(p, netfilter.NF_ACCEPT)
			}
		}()

		time.Sleep(time.Second * 10)

		nfq2.Close()
	}

	p.nfq = new(nfqueue.Queue)

	// TODO: this assumes a global Processor singleton...
	// there are some cgo issues here... and dragons...
	p.nfq.SetCallback(routeOnPacket)

	err = p.nfq.Init()
	if err != nil {
		return
	}

	err = p.nfq.Unbind(syscall.AF_INET)
	if err != nil {
		return
	}

	err = p.nfq.Bind(syscall.AF_INET)
	if err != nil {
		return
	}

	// TODO: multiple queues. easy.
	err = p.nfq.CreateQueue(0)
	if err != nil {
		return
	}

	/*
		h, err := pcap.OpenLive("wlan0", 1, false, time.Second)
		if err != nil {
			p.log.Error(err)
		}

		instuctions, err := h.CompileBPFFilter("tcp portrange 9000-9200")
		if err != nil {
			p.log.Error(err)
		}

		if h != nil {
			h.Close()
		}

		vm := pcapBPFToXNetBPF(instuctions)

		out, err := vm.Run([]byte{
			0xcc, 0x5d, 0x4e, 0x06, 0x51, 0x9b, 0x88, 0x53, 0x2e, 0x69, 0x37, 0x64, 0x08, 0x00, 0x45, 0x00,
			0x00, 0x3c, 0x6d, 0xc8, 0x40, 0x00, 0x40, 0x06, 0x98, 0xea, 0xc0, 0xa8, 0x00, 0x50, 0x34, 0xd6,
			0x3e, 0x3b, 0x80, 0xc0, 0x23, 0xf0, 0xb4, 0xd9, 0x20, 0x79, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
			0x72, 0x10, 0xd9, 0xb9, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x78,
			0x4d, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
		})

		p.log.Infof("%v %v", out, err)
	*/

	return
}

func (p *Processor) PacketsProcessed() uint64 {
	return atomic.LoadUint64(&p.packetsProcessed)
}

func (p *Processor) Stop() (err error) {
	close(p.stop)
	return
}

func (p *Processor) Cleanup() (err error) {
	// debug.PrintStack()
	p.cleanupOnce.Do(func() {
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

// TODO: stop chan struct{}
func (p *Processor) Start() (err error) {
	p.log.Infof("starting freki on %s", p.publicAddr)

	go func() {
		ticker := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-ticker.C:
				p.Connections.FlushOlderThan(time.Second * 60)
			case <-p.stop:
				ticker.Stop()
				return
			}
		}
	}()

	p.nfq.TryRun()
	return
}

const hijackTCPServerPort = 6000

var localhost = net.ParseIP("127.0.0.1")

func (p *Processor) hijackTCP(payload *nfqueue.Payload, packet gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP, body *gopacket.Payload) (err error) {
	/*
		if tcp.SrcPort != 22 && tcp.DstPort != 22 {
			p.log.Debugf("packet %+v %+v", ip, tcp)
		}
	*/

	if ip.SrcIP.Equal(p.publicAddr) {
		// packets back to client
		if tcp.SrcPort != hijackTCPServerPort {
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

		//p.log.Debugf("outboud %+v %+v", ip, tcp)

		tcp.SrcPort = md.TargetPort
	} else {
		// packets to honeypot
		if tcp.DstPort == 22 {
			payload.SetVerdict(nfqueue.NF_ACCEPT)
			return
		}

		ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
		md := p.Connections.GetByFlow(ck)

		if md == nil {
			// not tracking
			payload.SetVerdict(nfqueue.NF_ACCEPT)
			return
		}

		tcp.DstPort = hijackTCPServerPort
	}

	tcp.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, body,
	)

	if err != nil {
		return
	}

	err = payload.SetVerdictModified(nfqueue.NF_ACCEPT, buffer.Bytes())

	return
}

func (p *Processor) onPacket(payload *nfqueue.Payload) (retVal int) {
	retVal = 0 // see: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html
	// TODO: remove defer
	defer func() {
		atomic.AddUint64(&p.packetsProcessed, 1)
	}()

	// TODO: set DecodeOptions
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	var (
		ip   layers.IPv4
		tcp  layers.TCP
		udp  layers.UDP
		icmp layers.ICMPv4
		body gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&body)

	var foundLayerTypes []gopacket.LayerType
	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)

	if err != nil {
		p.log.Error(err, foundLayerTypes)
		payload.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	for _, layer := range foundLayerTypes {
		switch layer {
		//case layers.LayerTypeDNS:
		//	p.log.Infof("%+v", dns.Questions)
		case layers.LayerTypeTCP:

			// example drop
			/*
				if tcp.DstPort == 4000 {
					payload.SetVerdict(nfqueue.NF_DROP)
					return
				}
			*/

			// TODO: validate
			if tcp.SYN && !tcp.ACK {
				// when i don't respond to a SYN, then a duplicate SYN is sent
				ck := NewConnKeyByEndpoints(ip.NetworkFlow().Src(), tcp.TransportFlow().Src())
				p.Connections.Register(ck, tcp.DstPort, ip.DstIP.To4())
			}

			err = p.hijackTCP(payload, packet, &ip, &tcp, &body)

			if err != nil {
				p.log.Error(err)
			}

			return

			//case layers.LayerTypeICMPv4:
			//	p.log.Infof("%+v", icmp,)
		}
	}

	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return
}

func routeOnPacket(payload *nfqueue.Payload) int {
	return processor.onPacket(payload)
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
		// p.log.Error(err)
	}

	return vm
}
