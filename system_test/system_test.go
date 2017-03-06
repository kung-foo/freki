package system_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

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

				body, err := ioutil.ReadAll(resp.Body)
				So(err, ShouldBeNil)
				So(bytes.Equal(body, []byte("OK\n")), ShouldBeTrue)
				resp.Body.Close()
			}

			f(80)
			f(8080)
		})

		Convey("Port 1137 should proxy to port.party:666", func() {
			resp, err := http.Get("http://freki:1337/cors.json")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			So(resp.StatusCode, ShouldEqual, 200)

			body, err := ioutil.ReadAll(resp.Body)
			So(err, ShouldBeNil)

			j := make(map[string]int)

			So(json.Unmarshal(body, &j), ShouldBeNil)

			So(j, ShouldContainKey, "Port")
			So(j["Port"], ShouldEqual, 666)

			resp.Body.Close()
		})
	})
}
