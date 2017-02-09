# HTTP Proxy example

This shows how **freki** can be used to route multiple ports to a standard
HTTP proxy. Any request to the container running **freki** on ports 5000-5010
will be proxyied on to a container running [tinyproxy](https://tinyproxy.github.io/).

```
$ docker-compose build
...
$ docker-compose up
Starting httpproxy_tinyproxy_1
Starting httpproxy_freki_1
Attaching to httpproxy_tinyproxy_1, httpproxy_freki_1
tinyproxy_1  | Starting tinyproxy: tinyproxy.
...
freki_1  | time="2017-02-08T10:39:03Z" level=info msg="[freki   ] starting freki on [172.18.0.3]"
freki_1  | time="2017-02-08T10:39:03Z" level=info msg="[freki   ] starting proxy.tcp on 6002"
freki_1  | time="2017-02-08T10:39:03Z" level=info msg="[freki   ] starting log.tcp on 6000"
freki_1  | time="2017-02-08T10:39:03Z" level=info msg="[freki   ] starting log.http on 6001"
```

And in another shell using the IP address of the freki container (172.18.0.3):

```
$ curl --proxy http://172.18.0.3:5001 http://ipinfo.io
{
  "ip": "1.2.3.4",
  "hostname": "No Hostname",
  "city": "Oslo",
  "region": "Oslo",
  "country": "NO",
  "loc": "0,0",
  "org": "",
  "postal": ""
}
```
