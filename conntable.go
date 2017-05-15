package freki

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Ckey is a key representing a connection
type Ckey [2]uint64

var (
	// TODO: should this match net.nf_conntrack_max?
	initialTableSize = 262144
	connTimeout      = time.Second * 600
)

var (
	ErrUntrackedConnection = errors.New("untracked connection")
)

// TODO: look at using FlowFromEndpoints(...)
// NewConnKeyByEndpoints returns a key from an endpoint pair
func NewConnKeyByEndpoints(clientAddr gopacket.Endpoint, clientPort gopacket.Endpoint) Ckey {
	if clientAddr.EndpointType() != layers.EndpointIPv4 {
		panic("clientAddr endpoint must be of type layers.EndpointIPv4")
	}

	if clientPort.EndpointType() != layers.EndpointTCPPort && clientPort.EndpointType() != layers.EndpointUDPPort {
		panic("clientPort endpoint must be of type layers.EndpointTCPPort or layers.EndpointUDPPort")
	}

	return Ckey{clientAddr.FastHash(), clientPort.FastHash()}
}

// NewConnKeyByString returns a key from a connection pair as string
func NewConnKeyByString(host, port string) Ckey {
	clientAddr := layers.NewIPEndpoint(net.ParseIP(host).To4())
	p, _ := strconv.Atoi(port)
	clientPort := layers.NewTCPPortEndpoint(layers.TCPPort(p))
	return NewConnKeyByEndpoints(clientAddr, clientPort)
}

// NewConnKeyFromNetConn returns a key from a connection
func NewConnKeyFromNetConn(conn net.Conn) Ckey {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return NewConnKeyByString(host, port)
}

// Metadata in the connection table
type Metadata struct {
	Added       time.Time
	LastUpdated int64
	Rule        *Rule
	TargetPort  uint16
}

type connTable struct {
	table     map[Ckey]*Metadata
	mtx       sync.RWMutex
	softLimit int // softLimit controls when the cleanup routine is invoked
}

func newConnTable(softLimit int) *connTable {
	if softLimit < initialTableSize {
		softLimit = initialTableSize
	}
	ct := &connTable{
		table:     make(map[Ckey]*Metadata, initialTableSize),
		softLimit: softLimit,
	}
	return ct
}

// TODO: fix srcIP string inconsistency
func (t *connTable) Register(ck Ckey, matchedRule *Rule, srcIP, srcPort string, targetPort uint16) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if _, ok := t.table[ck]; ok {
		// TODO: wut?
	} else {
		logger.Debugf("[contable] registering %s:%s->%d", srcIP, srcPort, targetPort)
		now := time.Now()
		t.table[ck] = &Metadata{
			Added:       now,
			LastUpdated: now.UnixNano(),
			Rule:        matchedRule,
			TargetPort:  targetPort,
		}
	}
}

func (t *connTable) FlushOlderOnes() int {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	now := time.Now()
	minutes := 30
	flushed := 0

	for minutes >= 0 {
		duration := time.Duration(minutes) * time.Minute
		threshold := now.Add(-1 * duration).UnixNano()

		for ck, md := range t.table {
			if md.LastUpdated < threshold {
				delete(t.table, ck)
				flushed++
			}
		}

		if len(t.table) < t.softLimit {
			break
		} else {
			minutes -= 10
		}
	}
	return flushed
}

func (t *connTable) updatePacketTime(ck Ckey) error {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	if _, ok := t.table[ck]; ok {
		atomic.StoreInt64(&t.table[ck].LastUpdated, time.Now().UnixNano())
		return nil
	}

	return ErrUntrackedConnection
}

// TODO: what happens when I return a *Metadata and then FlushOlderThan()
// deletes it?
func (t *connTable) GetByFlow(ck Ckey) *Metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	return t.table[ck]
}

func (t *connTable) dump() {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	var buffer bytes.Buffer

	for ck, md := range t.table {
		buffer.WriteString(fmt.Sprintf("%v %+v\n", ck, md))
	}

	logger.Infof("\n%s", buffer.String())
}
