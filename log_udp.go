package freki

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/pkg/errors"
)

const (
	udpReadDeadline = time.Second
)

// UDPLogger struct
type UDPLogger struct {
	port      uint
	readSize  uint
	processor *Processor
	conn      *net.UDPConn
}

// NewUDPLogger creates an instace of the logger
func NewUDPLogger(port uint, readSize uint) *UDPLogger {
	return &UDPLogger{
		port:     port,
		readSize: readSize,
	}
}

// Port of the logger
func (h *UDPLogger) Port() uint {
	return h.port
}

// Type of the logger
func (h *UDPLogger) Type() string {
	return "log.udp"
}

// Start the UDP logger
func (h *UDPLogger) Start(p *Processor) error {
	h.processor = p

	var err error
	h.conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: int(h.port)})

	if err != nil {
		return err
	}

	buffer := make([]byte, h.readSize)

	for {
		// h.conn.SetReadDeadline(time.Now().Add(udpReadDeadline))
		n, addr, err := h.conn.ReadFrom(buffer)

		if err != nil {
			logger.Error(errors.Wrap(err, h.Type()))
			continue
		}

		logger.Infof("[log.udp ] %d %v %v\n%s", n, addr, err, hex.Dump(buffer[0:n]))
	}
}

// Shutdown the UDP logger
func (h *UDPLogger) Shutdown() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}
