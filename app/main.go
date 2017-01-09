package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/kung-foo/freki"
	log "github.com/sirupsen/logrus"
)

func onErrorExit(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fn()
	}()
}

func main() {
	// log.SetLevel(log.DebugLevel)

	processor := freki.New()

	err := processor.Init()
	onErrorExit(err)

	exit := func() {
		err := processor.Stop()
		if err != nil {
			log.Error(err)
		}
		onErrorExit(processor.Cleanup())
		os.Exit(0)
	}

	defer exit()
	onInterruptSignal(exit)

	go func() {
		pp := uint64(0)
		for range time.NewTicker(time.Second * 5).C {
			t := processor.PacketsProcessed()
			pps := (t - pp) / uint64(5)
			log.Debugf("PPS: %d", pps)
			pp = t
		}
	}()

	// TODO: move
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, port, _ := net.SplitHostPort(r.RemoteAddr)
		log.Infof("http %s %s", host, port)
		ck := freki.NewConnKeyByString(host, port)
		md := processor.Connections.GetByFlow(ck)
		//fmt.Fprintf(w, "Hello on port %d\n", md.TargetPort)
		log.Infof("%s -> %s", host, md.TargetPort.String())
		fmt.Fprintf(w, "OK")
	})

	go http.ListenAndServe(":8080", nil)

	go func() {
		ln, err := net.Listen("tcp", ":6000")
		onErrorExit(err)

		for {
			conn, err := ln.Accept()
			onErrorExit(err)

			go func(conn net.Conn) {
				conn.SetReadDeadline(time.Now().Add(time.Second * 5))
				host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
				ck := freki.NewConnKeyByString(host, port)
				md := processor.Connections.GetByFlow(ck)
				log.Infof("%s -> %s", host, md.TargetPort)
				buffer := make([]byte, 1024)
				n, _ := conn.Read(buffer)
				hex.Dumper(log.StandardLogger().Writer()).Write(buffer[0:n])
				err := conn.Close()
				if err != nil {
					log.Error(err)
				}
			}(conn)
		}
	}()

	// TODO: pass in stop channel
	processor.Start()
}
