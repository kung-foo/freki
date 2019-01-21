package freki

import (
	"fmt"
	"net"
	"runtime/debug"

	"github.com/pkg/errors"
)

// UserConnServer type struct
type UserConnServer struct {
	port      uint
	processor *Processor
	listener  net.Listener
	process   bool
}

// NewUserConnServer returns a user defined connection server type
func NewUserConnServer(port uint) *UserConnServer {
	return &UserConnServer{
		port:    port,
		process: true,
	}
}

// Port of the connection server
func (h *UserConnServer) Port() uint {
	return h.port
}

// Type of the connection server
func (h *UserConnServer) Type() string {
	return "user.tcp"
}

// Start the connection server
func (h *UserConnServer) Start(processor *Processor) error {
	h.processor = processor

	var err error
	// TODO: can I be more specific with the bind addr?
	h.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", h.port))

	if err != nil {
		return err
	}

	for h.process {
		conn, err := h.listener.Accept()
		if err != nil {
			logger.Errorf("[user.tcp] %v", err)
			continue
		}

		ck, err := NewConnKeyFromNetConn(conn)
		if err != nil {
			return err
		}
		md := h.processor.Connections.GetByFlow(ck)

		if md == nil {
			logger.Warnf("[user.tcp] untracked connection: %s", conn.RemoteAddr().String())
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
						logger.Errorf("[user.tcp] panic: %+v", r)
						logger.Errorf("[user.tcp] stacktrace:\n%v", string(debug.Stack()))
						conn.Close()
					}
				}()
				err := hfunc(conn, md)
				if err != nil {
					logger.Error(errors.Wrap(err, h.Type()))
				}
			}()
		} else {
			logger.Errorf("[user.tcp] %v", fmt.Errorf("no handler found for %s", md.Rule.Target))
			conn.Close()
			continue
		}
	}
	return nil
}

// Shutdown the connection server
func (h *UserConnServer) Shutdown() error {
	h.process = false
	if h.listener != nil {
		return h.listener.Close()
	}
	return nil
}
