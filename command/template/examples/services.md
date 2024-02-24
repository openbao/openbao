Querying all services with Consul Template
------------------------------------------
As of Consul Template 0.6.0, it is possible to have a complex dependency graph with dependent services. As such, it is possible to query and watch all services in Consul:

## Query All Services

```liquid
{{range services}}# {{.Name}}{{range service .Name}}
{{.Address}}{{end}}

{{end}}
```

Save this file to disk at a place reachable by the Consul Template process like `/tmp/all.ctmpl` and run Consul Template:

```shell
$ consul-template \
  -template="/tmp/all.ctmpl:/tmp/all"
```

Here is an example of what the file may render:

```text
# consul
104.131.121.232

# redis
104.131.86.92
104.131.109.224
104.131.59.59

# web
104.131.86.92
104.131.109.224
104.131.59.59
```
