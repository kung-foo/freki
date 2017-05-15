FROM golang:1.8-alpine

RUN apk update && apk add curl build-base iptables libpcap-dev "libnetfilter_queue-dev>=1.0.0" git gcc libc-dev linux-headers
RUN go get golang.org/x/net/bpf
RUN go get golang.org/x/net/context
RUN go get golang.org/x/net/proxy
RUN go get github.com/smartystreets/goconvey
RUN go get github.com/miekg/dns

WORKDIR /go/src/github.com/kung-foo/freki

RUN curl -s -L https://github.com/kung-foo/waitforit/releases/download/v0.0.1/waitforit-linux-amd64 > /bin/waitforit
RUN chmod +x /bin/waitforit
