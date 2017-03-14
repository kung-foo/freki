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

func NewConnKeyFromNetConn(conn net.Conn) ckey {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return NewConnKeyByString(host, port)
}

type Metadata struct {
	Added      time.Time
	Rule       *Rule
	TargetPort uint16
	//TargetIP   net.IP
}

type connTable struct {
	table map[ckey]*Metadata
	mtx   sync.RWMutex
}

func newConnTable() *connTable {
	ct := &connTable{
		table: make(map[ckey]*Metadata, 1024),
	}
	return ct
}

// TODO: fix srcIP string inconsistency
func (t *connTable) Register(ck ckey, matchedRule *Rule, srcIP, srcPort string, targetPort uint16) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if _, ok := t.table[ck]; ok {
		// TODO: wut?
	} else {
		logger.Debugf("[contable] registering %s:%s->%d", srcIP, srcPort, targetPort)

		t.table[ck] = &Metadata{
			Added:      time.Now(),
			Rule:       matchedRule,
			TargetPort: targetPort,
			//TargetIP:   targetIP,
		}
	}
}

func (t *connTable) FlushOlderThan(s time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	threshold := time.Now().Add(-1 * s)

	for ck, md := range t.table {
		if md.Added.Before(threshold) {
			delete(t.table, ck)
		}
	}
}

// TODO: what happens when I return a *Metadata and then FlushOlderThan()
// deletes it?
func (t *connTable) GetByFlow(ck ckey) *Metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.table[ck]
}
