package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/kung-foo/freki/netfilter"
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

// iptables -A INPUT -j NFQUEUE --queue-num 0
// iptables -A OUTPUT -j NFQUEUE --queue-num 0

func main() {
	q, err := netfilter.New(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	onErrorExit(err)

	pp := 0

	onInterruptSignal(func() {
		q.Close()
		log.Printf("\n%d packets processed", pp)
		os.Exit(0)
	})

	go q.Run()

	pChan := q.Packets()

	for p := range pChan {
		q.SetVerdict(p, netfilter.NF_ACCEPT)
		pp++
	}
}
