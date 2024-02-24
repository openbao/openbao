Joining Structures with Consul Template
---------------------------------------
Consul Template has built-in support for joining existing arrays and lists on a given separator, but there is no built-in support for complex map-reduce functions. This section details some common join techniques.

## Joining Service Addresses
Sometimes you require all service addresses to be listed in a comma-separated list. Memcached and other tools usually accept this as an environment variable.


```liquid
export MEMCACHED_SERVERS="{{range $index, $service := service "memcached" }}{{if ne $index 0}},{{end}}{{$service.Address}}:{{$service.Port}}{{end}}"
```

Save this file to disk at a place reachable by the Consul Template process like `/tmp/memcached.ctmpl` and run Consul Template:

```shell
$ consul-template \
  -template="/tmp/memcached.ctmpl:/etc/profile.d/memcached"
```

Here is an example of what the file may render:

```text
export MEMCACHED_SERVERS="1.2.3.4,5.6.7.8"
```

- For a list of functions, please see the [Consul Template README](https://github.com/hashicorp/consul-template)
- For template syntax, please see [the golang text/template documentation](https://golang.org/pkg/text/template/)
