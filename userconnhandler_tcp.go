package freki

import (
	"fmt"
	"net"
	"runtime/debug"

	"github.com/pkg/errors"
)

type UserConnServer struct {
	port      uint
	processor *Processor
	log       Logger
	listener  net.Listener
}

func NewUserConnServer(port uint) *UserConnServer {
	return &UserConnServer{
		port: port,
	}
}

func (h *UserConnServer) Port() uint {
	return h.port
}

func (h *UserConnServer) Type() string {
	return "user.tcp"
}

func (h *UserConnServer) Start(processor *Processor) error {
	h.processor = processor
	h.log = h.processor.log

	var err error
	// TODO: can I be more specific with the bind addr?
	h.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", h.port))

	if err != nil {
		return err
	}

	for {
		conn, err := h.listener.Accept()
		if err != nil {
			h.log.Errorf("[user.tcp] %v", err)
			continue
		}

		ck := NewConnKeyFromNetConn(conn)
		md := h.processor.Connections.GetByFlow(ck)

		if md == nil {
			h.log.Warnf("[user.tcp] untracked connection: %s", conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		// TODO: there is no connection between freki and the handler
		// once freki starts to shutdown, handlers are not notified.
		// maybe use a Context?
		if hfunc, ok := h.processor.connHandlers[md.Rule.Target]; ok {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						h.log.Errorf("[user.tcp] panic: %+v", r)
						h.log.Errorf("[user.tcp] stacktrace:\n%v", string(debug.Stack()))
						conn.Close()
					}
				}()
				err := hfunc(conn, md)
				if err != nil {
					h.log.Error(errors.Wrap(err, h.Type()))
				}
			}()
		} else {
			h.log.Errorf("[user.tcp] %v", fmt.Errorf("no handler found for %s", md.Rule.Target))
			conn.Close()
			continue
		}
	}
}

func (h *UserConnServer) Shutdown() error {
	if h.listener != nil {
		return h.listener.Close()
	}
	return nil
}
