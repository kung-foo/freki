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
	Added       time.Time
	LastUpdated time.Time
	Rule        *Rule
	TargetPort  layers.TCPPort
	//TargetIP   net.IP
}

type connTable struct {
	table     map[ckey]*Metadata
	mtx       sync.RWMutex
	softLimit int // softLimit controls when the cleanup routine is invoked
}

func newConnTable(softLimit int) *connTable {
	ct := &connTable{
		table:     make(map[ckey]*Metadata, softLimit),
		softLimit: softLimit,
	}

	return ct
}

// TODO: fix srcIP string inconsistency
func (t *connTable) Register(ck ckey, matchedRule *Rule, srcIP, srcPort string, targetPort layers.TCPPort) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if _, ok := t.table[ck]; ok {
		// TODO: wut?
	} else {

		logger.Debugf("[contable] registering %s:%s->%d", srcIP, srcPort, targetPort)
		now := time.Now()
		t.table[ck] = &Metadata{
			Added:       now,
			LastUpdated: now,
			Rule:        matchedRule,
			TargetPort:  targetPort,
			//TargetIP:   targetIP,
		}

	}
}

func (t *connTable) FlushOlderOnes() {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	now := time.Now()

	minutes := 30

	for minutes >= 0 {

		duration := time.Duration(minutes) * time.Minute
		threshold := now.Add(-1 * duration)

		for ck, md := range t.table {
			if md.LastUpdated.Before(threshold) {
				delete(t.table, ck)
			}
		}

		if len(t.table) < t.softLimit {
			break
		} else {
			minutes -= 10
		}
	}
}

func (t *connTable) updatePacketTime(ck ckey) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	if _, ok := t.table[ck]; ok {
		t.table[ck].LastUpdated = time.Now()
	} else {
		// TODO
		// What?
	}

}

// TODO: what happens when I return a *Metadata and then FlushOlderThan()
// deletes it?
func (t *connTable) GetByFlow(ck ckey) *Metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.table[ck]
}
