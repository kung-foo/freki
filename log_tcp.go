package freki

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

var readDeadline = time.Second * 5

// TCPLogger struct
type TCPLogger struct {
	port      uint
	readSize  uint
	processor *Processor
	listener  net.Listener
}

// NewTCPLogger creates an instace of the logger
func NewTCPLogger(port uint, readSize uint) *TCPLogger {
	return &TCPLogger{
		port:     port,
		readSize: readSize,
	}
}

// Port of the logger
func (h *TCPLogger) Port() uint {
	return h.port
}

// Type of the logger
func (h *TCPLogger) Type() string {
	return "log.tcp"
}

// Start the TCP logger
func (h *TCPLogger) Start(p *Processor) error {
	h.processor = p

	var err error
	// TODO: can I be more specific with the bind addr?
	h.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", h.port))

	if err != nil {
		return err
	}

	for {
		conn, err := h.listener.Accept()
		if err != nil {
			logger.Error(errors.Wrap(err, h.Type()))
			continue
		}

		go func(conn net.Conn) {
			defer func() {
				err := conn.Close()
				if err != nil {
					logger.Error(errors.Wrap(err, h.Type()))
				}
			}()

			conn.SetReadDeadline(time.Now().Add(readDeadline))
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ck, err := NewConnKeyByString(host, port)
			if err != nil {
				logger.Error(err)
				return
			}
			md := h.processor.Connections.GetByFlow(ck)
			if md == nil {
				logger.Warnf("[log.tcp ] untracked connection: %s", conn.RemoteAddr().String())
				return
			}
			buffer := make([]byte, h.readSize)
			n, err := conn.Read(buffer)
			if err != nil {
				logger.Error(err)
				return
			}
			if n > 0 {
				logger.Infof("[log.tcp ] %s -> %v\n%s", host, md.TargetPort, hex.Dump(buffer[0:n]))
			} else {
				logger.Infof("[log.tcp ] %s -> %v", host, md.TargetPort)
			}
		}(conn)
	}
}

// Shutdown the TCP logger
func (h *TCPLogger) Shutdown() error {
	if h.listener != nil {
		return h.listener.Close()
	}
	return nil
}
