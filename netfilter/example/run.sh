#!/usr/bin/env bash
set -ex

trap cleanup INT TERM

cleanup() {
    iptables -D OUTPUT -j NFQUEUE --queue-num 0
    iptables -D INPUT -j NFQUEUE --queue-num 0
    exit
}

iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0

go run main.go
