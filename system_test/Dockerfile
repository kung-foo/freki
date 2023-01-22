FROM golang:1.18-alpine

RUN apk update && apk add curl build-base iptables libpcap-dev libnetfilter_queue-dev git gcc libc-dev linux-headers

WORKDIR /go/src/github.com/kung-foo/freki

RUN curl -s -L https://github.com/kung-foo/waitforit/releases/download/v0.0.1/waitforit-linux-amd64 > /bin/waitforit
RUN chmod +x /bin/waitforit
