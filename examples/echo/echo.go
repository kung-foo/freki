package main // github.com/kung-foo/freki/examples/echo

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/kung-foo/freki"
	log "github.com/sirupsen/logrus"
)

const echoHandlerName = "echo"

var frekiRules = fmt.Sprintf(`
rules:
  - match: tcp
    type: conn_handler
    target: %s
`, echoHandlerName)

func main() {
	iface := flag.String("interface", "any", "interface to bind to")
	flag.Parse()

	rules, err := freki.ParseRuleSpec([]byte(frekiRules))
	exitOnError(err)

	processor, err := freki.New(*iface, rules, log.StandardLogger())
	exitOnError(err)

	processor.AddServer(freki.NewUserConnServer(6000))

	processor.RegisterConnHandler(echoHandlerName, echo)

	exitOnError(processor.Init())

	goodbye := func() {
		processor.Shutdown()
		os.Exit(0)
	}

	go func() {
		processor.Start()
		goodbye()
	}()

	onInterruptSignal(func() {
		println()
		goodbye()
	})

	runtime.Goexit()
}

func echo(conn net.Conn, md *freki.Metadata) error {
	const timeout = time.Second * 5

	defer conn.Close()

	log.Printf("[echo    ] new conn: %v --> %d", conn.RemoteAddr(), md.TargetPort)

	b := bufio.NewReader(conn)

	for {
		conn.SetDeadline(time.Now().Add(timeout))
		line, err := b.ReadBytes('\n')
		if err != nil {
			break
		}
		fmt.Fprintf(conn, "hello on: %d\n%s", md.TargetPort, line)
	}

	return nil
}

func exitOnError(err error) {
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
