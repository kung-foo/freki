#!/usr/bin/env ash

set -ex

env GO111MODULE=on go build -o /tmp/freki app/main.go
exec /tmp/freki -v -i eth0 -r system_test/rules.yaml
