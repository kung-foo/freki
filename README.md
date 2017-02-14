freki
=====

The ravenous and greedy one.

**Freki** is a tool for manipulating packets in userspace. Using iptable's raw table, packets are routed down into userspace where **freki** takes over. A set of rules is applied allowing for a large amount of flexibility. For example, you can forward all TCP ports to an HTTP honeypot and log the requests. Or you can proxy TCP port 22 into a docker container running an ssh honeypot.

There are currently two builtin loggers:

`log_tcp`: reads up to 1024 bytes from the connection, and then closes it.

`log_http`: sends a 200 OK back on every request.

Additionally, there are two mangling behaviours:

`rewrite`: Rewrites the incoming packet's destination port

`proxy`: Creates a TCP proxy for the connection to the specified target (can be an IP address, host name, or docker container)

```
$ ./bin/freki --help
Usage:
    freki [options] [-v ...] -i=<interface> -r=<rules>
    freki -h | --help | --version
Options:
    -i --interface=<iface>  Bind to this interface.
    -r --rules=<rules>      Rules file.
    -h --help               Show this screen.
    --version               Show version.
    -v                      Enable verbose logging (-vv for very verbose)
```

Build
-----

requires: go 1.7+, libnetfilter-queue-dev, libpcap-dev, iptables-dev


Rules Specification
-------------------

Rules are applied in order (top down) and stop after a match is found. The `match` field (required) is written using [BPF filter](https://biot.com/capstats/bpf.html) syntax. Note: not all filters may apply. For example, the ethernet src and dst headers are generally zero'd out.

```yaml
rules:
  # allow packets from your machine (1.2.3.4) to reach your ssh server
  - match: tcp dst port 22 and src host 1.2.3.4
    type: passthrough
  # send all tcp coming in on 10022 to 22
  - match: tcp dst port 10022
    type: rewrite
    target: 22
  # proxy all packets coming in on 6379 on to a container named 'redis' (must exist at the time freki starts)
  - match: tcp dst port 6379
    type: proxy
    target: docker://redis:6379
  # proxy all packets coming in on 666 out to portquiz.net:666
  - match: tcp dst port 666
    type: proxy
    target: tcp://portquiz.net:666
  # log http requests on 80 and 8080
  - match: tcp port 80 or tcp port 8080
    type: log_http
  # drop (no FIN, nothing!)
  - match: tcp portrange 5000-5010
    type: drop
  # forward all remaining tcp packets to a tcp logger. grabs 1024 bytes and then closes.
  - match: tcp
    type: log_tcp
  - match:
    type: passthrough
```

Notes
-----

If **freki** hangs or panics, it may leave two iptables rules in place.

The simple fix is: `sudo iptables -t raw -F`.

Contributors
------------

* [Jonathan Camp](https://keybase.io/kung_foo)
* [glasos](https://keybase.io/glaslos)

License
-------
_freki_ is distributed under the terms of the MIT License.
