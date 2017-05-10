package freki

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
)

// HTTPLogger struct
type HTTPLogger struct {
	port uint
	//maxReadSize uint
	processor *Processor
}

// NewHTTPLogger creates an instace of the logger
func NewHTTPLogger(port uint) *HTTPLogger {
	return &HTTPLogger{
		port: port,
	}
}

// Port of the logger
func (h *HTTPLogger) Port() uint {
	return h.port
}

// Type of the logger
func (h *HTTPLogger) Type() string {
	return "log.http"
}

// Start the HTTP logger
func (h *HTTPLogger) Start(p *Processor) error {
	h.processor = p

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, port, _ := net.SplitHostPort(r.RemoteAddr)
		ck := NewConnKeyByString(host, port)
		md := h.processor.Connections.GetByFlow(ck)
		logger.Infof("[log.http] %s -> %d\n%s %s\n%v",
			host,
			md.TargetPort,
			r.Method, r.URL,
			r.Header)

		if r.Body != nil {
			defer r.Body.Close()
			body, _ := ioutil.ReadAll(r.Body)
			if len(body) > 0 {
				logger.Infof("[log.http] %s -> %d\n%s",
					host,
					md.TargetPort,
					hex.Dump(body),
				)
			}
		}

		fmt.Fprintf(w, "OK\n")
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", h.port), nil)
}

// Shutdown the HTTP logger
func (h *HTTPLogger) Shutdown() error {
	// TODO: go1.8 add server shutdown
	return nil
}
