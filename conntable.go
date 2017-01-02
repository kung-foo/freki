package freki

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var localhost = layers.NewIPEndpoint(net.ParseIP("127.0.0.1").To4())

type ckey [2]uint64

type metadata struct {
	added      time.Time
	TargetPort layers.TCPPort
}

type connTable struct {
	table map[ckey]metadata
	mtx   sync.RWMutex
}

func newConnTable() *connTable {
	ct := &connTable{
		table: make(map[ckey]metadata, 1024),
	}
	return ct
}

func (t *connTable) Register(network, transport gopacket.Flow, targetPort layers.TCPPort) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ck := ckey{network.FastHash(), transport.Src().FastHash()}

	t.table[ck] = metadata{
		added:      time.Now(),
		TargetPort: targetPort,
	}
}

// TODO: how should I make this clear that I am assuming the _reverse_ direction?
func (t *connTable) GetByFlow(network, transport gopacket.Flow) metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	ck := ckey{network.FastHash(), transport.Dst().FastHash()}
	//log.Infof("%+v %+v", network, t.table[ck])

	return t.table[ck]
}

// TODO: de-uglify
func (t *connTable) GetByRemoteAddr(host, port string) metadata {
	n, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.ParseIP(host).To4()), localhost)
	p, _ := strconv.Atoi(port)
	tcp := gopacket.NewFlow(layers.EndpointTCPPort, nil, layers.NewTCPPortEndpoint(layers.TCPPort(p)).Raw())

	return t.GetByFlow(n, tcp)
}
