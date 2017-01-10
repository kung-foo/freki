package freki

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ckey [2]uint64

func NewConnKeyByEndpoints(clientAddr gopacket.Endpoint, clientPort gopacket.Endpoint) ckey {
	if clientAddr.EndpointType() != layers.EndpointIPv4 {
		panic("clientAddr endpoint must be of type layers.EndpointIPv4")
	}

	if clientPort.EndpointType() != layers.EndpointTCPPort {
		panic("clientPort endpoint must be of type layers.EndpointTCPPort")
	}

	return ckey{clientAddr.FastHash(), clientPort.FastHash()}
}

func NewConnKeyByString(host, port string) ckey {
	clientAddr := layers.NewIPEndpoint(net.ParseIP(host).To4())
	p, _ := strconv.Atoi(port)
	clientPort := layers.NewTCPPortEndpoint(layers.TCPPort(p))
	return NewConnKeyByEndpoints(clientAddr, clientPort)
}

type metadata struct {
	added      time.Time
	TargetPort layers.TCPPort
	TargetIP   net.IP
}

type connTable struct {
	table map[ckey]*metadata
	mtx   sync.RWMutex
}

func newConnTable() *connTable {
	ct := &connTable{
		table: make(map[ckey]*metadata, 1024),
	}
	return ct
}

func (t *connTable) Register(ck ckey, targetPort layers.TCPPort, targetIP net.IP) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if _, ok := t.table[ck]; ok {
		// TODO: wut?
	} else {
		t.table[ck] = &metadata{
			added:      time.Now(),
			TargetPort: targetPort,
			TargetIP:   targetIP,
		}
	}
}

func (t *connTable) FlushOlderThan(s time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	threshold := time.Now().Add(-1 * s)

	for ck, md := range t.table {
		if md.added.Before(threshold) {
			delete(t.table, ck)
		}
	}
}

func (t *connTable) GetByFlow(ck ckey) *metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.table[ck]
}
