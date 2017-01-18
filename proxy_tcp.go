package freki

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pkg/errors"
)

type TCPProxy struct {
	port      uint
	processor *Processor
	log       Logger
	listener  net.Listener
}

func NewTCPProxy(port uint) *TCPProxy {
	return &TCPProxy{
		port: port,
	}
}

func (p *TCPProxy) Port() uint {
	return p.port
}

func (p *TCPProxy) Type() string {
	return "proxy.tcp"
}

func (p *TCPProxy) Start(processor *Processor) error {
	p.processor = processor
	p.log = p.processor.log

	var err error
	// TODO: can I be more specific with the bind addr?
	p.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.port))

	if err != nil {
		return err
	}

	for {
		conn, err := p.listener.Accept()

		if err != nil {
			p.log.Error(errors.Wrap(err, p.Type()))
			continue
		}

		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(conn net.Conn) {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ck := NewConnKeyByString(host, port)
	md := p.processor.Connections.GetByFlow(ck)
	if md == nil {
		p.log.Warnf("[prxy.tcp] untracked connection: %s", conn.RemoteAddr().String())
		return
	}

	target := md.Rule.targetURL

	if target.Scheme != "tcp" {
		p.log.Error(fmt.Errorf("unsuppported scheme: %s", target.Scheme))
		return
	}

	p.log.Infof("[prxy.tcp] %s -> %s to %s", host, md.TargetPort, target.String())

	proxyConn, err := net.DialTimeout("tcp", target.Host, time.Second*5)

	if err != nil {
		p.log.Error(errors.Wrap(err, p.Type()))
		return
	}

	go func() {
		_, err := io.Copy(proxyConn, conn)
		if err != nil {
			p.log.Error(errors.Wrap(err, p.Type()))
		}
	}()

	go func() {
		_, err := io.Copy(conn, proxyConn)
		if err != nil {
			p.log.Error(errors.Wrap(err, p.Type()))
		}
	}()
}

func (p *TCPProxy) Shutdown() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}
