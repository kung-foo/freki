package system_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEndToEnd(t *testing.T) {
	Convey("Given freki is working...", t, func() {
		Convey("Port 80 and 8080 should return OK", func() {
			f := func(p int) {
				resp, err := http.Get(fmt.Sprintf("http://freki:%d/", p))

				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)

				So(resp.StatusCode, ShouldEqual, 200)

				body, err := io.ReadAll(resp.Body)
				So(err, ShouldBeNil)
				So(bytes.Equal(body, []byte("OK\n")), ShouldBeTrue)
				resp.Body.Close()
			}

			f(80)
			f(8080)
		})

		Convey("Port 1137 should proxy to port.party:666", func() {
			resp, err := http.Get("http://freki:1337/json")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			So(resp.StatusCode, ShouldEqual, 200)

			body, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)

			j := make(map[string]string)

			So(json.Unmarshal(body, &j), ShouldBeNil)

			So(j, ShouldContainKey, "slideshow")

			resp.Body.Close()
		})

		Convey("Port 7000 to 8000 should echo", func() {
			f := func(p int) {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("freki:%d", p), time.Second)

				So(err, ShouldBeNil)
				So(conn, ShouldNotBeNil)

				defer conn.Close()

				msg := []byte(fmt.Sprintf("hello on %d\n", p))

				n, err := conn.Write(msg)

				So(err, ShouldBeNil)
				So(n, ShouldEqual, len(msg))

				b := bufio.NewReader(conn)

				line, err := b.ReadBytes('\n')

				So(err, ShouldBeNil)
				So(bytes.Equal(line, msg), ShouldBeTrue)
			}

			f(7000)
			f(7999)
		})
	})
}
