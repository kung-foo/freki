freki
=====

The ravenous and greedy one.

Rules Specification
-------------------

Rules are applied in order (top down) and stop after a match is found. The `match` field (required) is written using [BPF filter](https://biot.com/capstats/bpf.html) syntax. Note: not all filters make apply. For example, the ethernet src and dst headers are generally zero'd out.

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

License
-------
_freki_ is distributed under the terms of the MIT License.
