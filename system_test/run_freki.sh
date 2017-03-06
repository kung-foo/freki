#!/usr/bin/env ash

set -ex

go build -o /tmp/freki app/main.go
exec /tmp/freki -v -i eth0 -r system_test/rules.yaml
