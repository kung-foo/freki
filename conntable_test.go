package freki

import (
	"net"
	"strconv"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

var hostString = "0.0.0.0"
var portString = "1337"

func TestConnKeyByString(t *testing.T) {
	tkey := Ckey{16482135430807676828, 12530673430870296333}
	ckey := NewConnKeyByString(hostString, portString)
	assert.Equal(t, tkey, ckey, "connection king does't match expected value")
}

func TestConnKeyByInvalidPort(t *testing.T) {
	clientAddr4 := layers.NewIPEndpoint(net.ParseIP(hostString).To4())
	p, _ := strconv.Atoi(portString)
	clientPort := layers.NewSCTPPortEndpoint(layers.SCTPPort(p))
	assert.Panics(t, func() { NewConnKeyByEndpoints(clientAddr4, clientPort) }, "No panic for invalid port")
}

func TestConnKeyByInvalidHost(t *testing.T) {
	clientAddr6 := layers.NewIPEndpoint(net.ParseIP(hostString).To16())
	p, _ := strconv.Atoi(portString)
	clientPortUDP := layers.NewUDPPortEndpoint(layers.UDPPort(p))
	assert.Panics(t, func() { NewConnKeyByEndpoints(clientAddr6, clientPortUDP) }, "No panic for invalid port")
}

type testConn interface {
	RemoteAddr() net.Addr
	Close() error
	LocalAddr() net.Addr
}
