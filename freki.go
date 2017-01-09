package freki

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kung-foo/nfqueue-go/nfqueue"
	log "github.com/sirupsen/logrus"
)

const table = "raw"

//const table = "filter"

var chains = []string{"PREROUTING", "OUTPUT"}

//var chains = []string{"INPUT", "POSTROUTING"}

func genRule(protocol, queuespec string) []string {
	return strings.Split(fmt.Sprintf("-p,%s,-j,NFQUEUE,--queue-num,%s", protocol, queuespec), ",")
}

var processor *Processor

type Processor struct {
	ipt              *iptables.IPTables
	rules            [][]string
	nfq              *nfqueue.Queue
	cleanupOnce      sync.Once
	Connections      *connTable
	packetsProcessed uint64
	stop             chan struct{}
	publicAddr       net.IP
}

func New() *Processor {
	processor = &Processor{
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
			/*
				var tmp []string
				if chain == "PREROUTING" {
					tmp = append([]string{"-i", "eth0"}, rule...)
				} else {
					tmp = append([]string{"-o", "eth0"}, rule...)
				}
			*/
			/*
				err = p.ipt.AppendUnique(table, chain, "-j", "LOG", "--log-prefix", fmt.Sprintf("%s: ", chain))
				if err != nil {
					log.Error(err)
				}
			*/

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
			/*
				var tmp []string
				if chain == "PREROUTING" {
					tmp = append([]string{"-i", "eth0"}, rule...)
				} else {
					tmp = append([]string{"-o", "eth0"}, rule...)
				}
			*/

			// p.ipt.Delete(table, chain, "-j", "LOG", "--log-prefix", fmt.Sprintf("%s: ", chain))

			err = p.ipt.Delete(table, chain, rule...)
			if err != nil {
				log.Errorf("error deleting \"%s %s\": %v", table, chain, err)
				// return
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
		log.Debugf("%s %s %+v", table, chain, filters)
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
	log.Debug("Processor:cleanup()")

	p.resetIPTables()

	if p.nfq != nil {
		p.nfq.Close()
	}

	for _, chain := range chains {
		filters, _ := p.ipt.List(table, chain)
		log.Debugf("%s %s %+v", table, chain, filters)
	}
	return
}

// TODO: stop chan struct{}
func (p *Processor) Start() (err error) {
	log.Infof("starting freki on %s", p.publicAddr)

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
			log.Debugf("packet %+v %+v", ip, tcp)
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

		//log.Debugf("outboud %+v %+v", ip, tcp)

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
		log.Error(err, foundLayerTypes)
		payload.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	for _, layer := range foundLayerTypes {
		switch layer {
		//case layers.LayerTypeDNS:
		//	log.Infof("%+v", dns.Questions)
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
				log.Error(err)
			}

			return

			//case layers.LayerTypeICMPv4:
			//	log.Infof("%+v", icmp,)
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
