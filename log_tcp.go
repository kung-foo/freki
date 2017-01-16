package freki

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

var readDeadline = time.Second * 5

type TCPLogger struct {
	port      uint
	readSize  uint
	processor *Processor
	log       Logger
	listener  net.Listener
}

func NewTCPLogger(port uint, readSize uint) *TCPLogger {
	return &TCPLogger{
		port:     port,
		readSize: readSize,
	}
}

func (h *TCPLogger) Port() uint {
	return h.port
}

func (h *TCPLogger) Type() string {
	return "log.tcp"
}

func (h *TCPLogger) Start(p *Processor) error {
	h.processor = p
	h.log = h.processor.log

	var err error
	h.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", h.port))

	if err != nil {
		return err
	}

	for {
		conn, err := h.listener.Accept()

		if err != nil {
			h.log.Error(errors.Wrap(err, h.Type()))
			continue
		}

		go func(conn net.Conn) {
			defer func() {
				err := conn.Close()
				if err != nil {
					h.log.Error(errors.Wrap(err, h.Type()))
				}
			}()

			conn.SetReadDeadline(time.Now().Add(readDeadline))
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ck := NewConnKeyByString(host, port)
			md := h.processor.Connections.GetByFlow(ck)
			if md == nil {
				p.log.Warnf("[log.tcp ] untracked connection: %s", conn.RemoteAddr().String())
				return
			}
			buffer := make([]byte, h.readSize)
			n, _ := conn.Read(buffer)
			p.log.Infof("%s -> %s\n%s", host, md.TargetPort, hex.Dump(buffer[0:n]))
		}(conn)
	}
}

func (h *TCPLogger) Shutdown() error {
	if h.listener != nil {
		return h.listener.Close()
	}
	return nil
}
