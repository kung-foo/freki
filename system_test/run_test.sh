#!/usr/bin/env ash

set -ex

echo "Wating for freki to start..."
waitforit -r 60 -s http://freki:80

go test -v system_test/system_test.go
