package freki

import (
	"fmt"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kung-foo/nfqueue-go/nfqueue"
	log "github.com/sirupsen/logrus"
)

var chains = []string{"INPUT", "OUTPUT"}

func genRule(protocol, queuespec string) []string {
	return strings.Split(fmt.Sprintf("-p,%s,-j,NFQUEUE,--queue-num,%s", protocol, queuespec), ",")
}

var processor *Processor

type ckey [2]gopacket.Flow

func (k *ckey) String() string {
	return fmt.Sprintf("%s:%s", k[0], k[1])
}

type Processor struct {
	ipt         *iptables.IPTables
	rules       [][]string
	nfq         *nfqueue.Queue
	cleanupOnce sync.Once

	incoming map[ckey]uint16
}

func New() *Processor {
	processor = &Processor{
		rules:    make([][]string, 0),
		incoming: make(map[ckey]uint16, 1024),
	}

	// TODO: customize protocols
	processor.rules = append(processor.rules,
		genRule("tcp", "0"),
		genRule("udp", "0"),
		genRule("icmp", "0"),
	)

	return processor
}

func (p *Processor) initIPTables() (err error) {
	for _, rule := range p.rules {
		for _, chain := range chains {
			err = p.ipt.AppendUnique("filter", chain, rule...)
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
			err = p.ipt.Delete("filter", chain, rule...)
			if err != nil {
				log.Errorf("error deleting \"filter %s\": %v", chain, err)
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
		filters, _ := p.ipt.List("filter", chain)
		log.Debugf("filter %s %+v", chain, filters)
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

func (p *Processor) Cleanup() (err error) {
	p.cleanupOnce.Do(func() {
		err = p.cleanup()
	})
	return
}

func (p *Processor) cleanup() (err error) {
	log.Debug("Processor:cleanup()")

	if p.nfq != nil {
		p.nfq.Close()
	}

	p.resetIPTables()

	for _, chain := range chains {
		filters, _ := p.ipt.List("filter", chain)
		log.Debugf("filter %s %+v", chain, filters)
	}
	return
}

// TODO: stop chan struct{}
func (p *Processor) Start() (err error) {
	p.nfq.TryRun()
	return
}

func (p *Processor) sendNewPacket(buffer gopacket.SerializeBuffer, payload *nfqueue.Payload, layers ...gopacket.SerializableLayer) {
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, layers...)
	if err != nil {
		log.Error(err)
	}
}

func (p *Processor) onPacket(payload *nfqueue.Payload) (retVal int) {
	retVal = 0 // see: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html
	verdict := nfqueue.NF_ACCEPT
	modified := false
	buffer := gopacket.NewSerializeBuffer()

	// TODO: remove defer
	defer func() {
		if modified {
			payload.SetVerdictModified(verdict, buffer.Bytes())
		} else {
			payload.SetVerdict(verdict)
		}
	}()

	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	var (
		ip   layers.IPv4
		tcp  layers.TCP
		udp  layers.UDP
		icmp layers.ICMPv4
		dns  layers.DNS
		body gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&dns,
		&body)

	var foundLayerTypes []gopacket.LayerType
	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)

	if err != nil {
		log.Error(err, foundLayerTypes)
		return
	}

	for _, layer := range foundLayerTypes {
		switch layer {
		//case layers.LayerTypeDNS:
		//	log.Infof("%+v", dns.Questions)
		case layers.LayerTypeTCP:
			// log.Infof("body: %+v", body)
			if tcp.DstPort >= 1000 && tcp.DstPort < 2000 {
				dstPort := uint16(tcp.DstPort)

				if tcp.SYN {

				} else {

				}
				tcp.DstPort = 8080
				k := ckey{ip.NetworkFlow(), tcp.TransportFlow()}

				p.incoming[k] = dstPort

				log.Infof("%+v, %+v", ip.NetworkFlow(), tcp.TransportFlow())
				log.Infof("%+v", p.incoming)

				// TODO: move into sendNewPacket
				tcp.SetNetworkLayerForChecksum(&ip)
				p.sendNewPacket(buffer, payload, &ip, &tcp, &body)
				return
			} else if tcp.SrcPort == 8080 {
				k := ckey{ip.NetworkFlow().Reverse(), tcp.TransportFlow().Reverse()}
				log.Infof("%d", p.incoming[k])
			}
			//case layers.LayerTypeICMPv4:
			//	log.Infof("%+v", icmp,)
		}
	}

	return
}

func routeOnPacket(payload *nfqueue.Payload) int {
	return processor.onPacket(payload)
}

/*
func newTransportFlow(tcp layers.TCP) gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointTCPPort, tcp.SrcPort, tcp.DstPort)
}
*/
