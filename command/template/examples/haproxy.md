HAProxy Consul Template Example
-------------------------------
HAProxy is a very common load balancer. You can read more about the HAProxy configuration file syntax in the [HAProxy documentation](http://www.haproxy.org/).

## Global Service Load Balancer
Here is an example template for rendering an HAProxy configuration file with Consul Template:

```liquid
global
    daemon
    maxconn {{key "service/haproxy/maxconn"}}

defaults
    mode {{key "service/haproxy/mode"}}{{range ls "service/haproxy/timeouts"}}
    timeout {{.Key}} {{.Value}}{{end}}

listen http-in
    bind *:8000{{range service "release.web"}}
    server {{.Node}} {{.Address}}:{{.Port}}{{end}}
```

Save this file to disk at a place reachable by the Consul Template process like `/tmp/haproxy.conf.ctmpl` and run Consul Template:

```shell
$ consul-template \
  -template="/tmp/haproxy.conf.ctmpl:/etc/haproxy/haproxy.conf"
```

Here is an example of what the file may render:

```text
global
    daemon
    maxconn 4

defaults
    mode default
    timeout 5

listen http-in
    bind *:8000
    server nyc3-worker-2 104.131.109.224:80
    server nyc3-worker-3 104.131.59.59:80
    server nyc3-worker-1 104.131.86.92:80
```

- For a list of functions, please see the [Consul Template README](https://github.com/hashicorp/consul-template)
- For template syntax, please see [the golang text/template documentation](https://golang.org/pkg/text/template/)
