FROM alpine:3.5

WORKDIR /root
ENV FREKI_VER v1.0.4

RUN apk update && apk add curl libpcap libnetfilter_queue iptables
RUN curl -L https://github.com/kung-foo/freki/releases/download/${FREKI_VER}/freki-musl > /usr/local/bin/freki
RUN chmod +x /usr/local/bin/freki
