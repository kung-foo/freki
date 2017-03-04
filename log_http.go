package freki

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
)

type HTTPLogger struct {
	port uint
	//maxReadSize uint
	processor *Processor
}

func NewHTTPLogger(port uint) *HTTPLogger {
	return &HTTPLogger{
		port: port,
	}
}

func (h *HTTPLogger) Port() uint {
	return h.port
}

func (h *HTTPLogger) Type() string {
	return "log.http"
}

func (h *HTTPLogger) Start(p *Processor) error {
	h.processor = p

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, port, _ := net.SplitHostPort(r.RemoteAddr)
		ck := NewConnKeyByString(host, port)
		md := h.processor.Connections.GetByFlow(ck)
		logger.Infof("[log.http] %s -> %s\n%s %s\n%v",
			host,
			md.TargetPort.String(),
			r.Method, r.URL,
			r.Header)

		if r.Body != nil {
			defer r.Body.Close()
			body, _ := ioutil.ReadAll(r.Body)
			if len(body) > 0 {
				logger.Infof("[log.http] %s -> %s\n%s",
					host,
					md.TargetPort.String(),
					hex.Dump(body),
				)
			}
		}

		fmt.Fprintf(w, "OK\n")
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", h.port), nil)
}

func (h *HTTPLogger) Shutdown() error {
	// TODO: go1.8 add server shutdown
	return nil
}
