package freki

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	hostString = "127.0.0.1"
	portString = "8080"
)

/*
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
*/

func TestConntable(t *testing.T) {
	Convey("Freki needs a working connection table", t, func() {
		Convey("setting softlimit to zero should then use initialTableSize", func() {
			ct := newConnTable(0)
			So(ct, ShouldNotBeNil)
			So(ct.softLimit, ShouldEqual, initialTableSize)
		})

		Convey("flushing an empty table should return zero connetctions flushed", func() {
			ct := newConnTable(0)
			So(ct.FlushOlderOnes(), ShouldEqual, 0)
		})

		Convey("connections keys should work", func() {
			// Note: if gopacket's fast hash impl changes, this will break
			local8080ck := Ckey{9580489724559085892, 10211785817824934042}

			ck, err := NewConnKeyByString("127.0.0.1", "8080")
			So(err, ShouldBeNil)
			So(ck, ShouldEqual, local8080ck)

			ip := layers.NewIPEndpoint(net.ParseIP("127.0.0.1").To4())
			port := layers.NewTCPPortEndpoint(8080)
			ck, err = NewConnKeyByEndpoints(ip, port)
			So(err, ShouldBeNil)
			So(ck, ShouldEqual, local8080ck)

			l, err := net.Listen("tcp", "127.0.0.1:8080")
			So(err, ShouldBeNil)

			conn, err := net.Dial("tcp", "127.0.0.1:8080")
			So(err, ShouldBeNil)

			ck, err = NewConnKeyFromNetConn(conn)
			So(err, ShouldBeNil)
			So(ck, ShouldEqual, local8080ck)
			l.Close()
		})
	})
}
