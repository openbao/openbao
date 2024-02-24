Apache Consul Template Example
------------------------------
Apache httpd is a popular web server. You can read more about the Apache httpd configuration file syntax in the [Apache httpd documentation](https://httpd.apache.org/docs/).


## Reverse Proxy based on Service Tags
Here is an example template for rendering part of an Apache httpd configuration file that is responsible for configuring a reverse proxy with dynamic end points based on service tags with Consul Template:

```liquid
{{range $tag, $service := service "web" | byTag}}
# "{{$tag}}" api providers.
<Proxy balancer://{{$tag}}>
{{range $service}}  BalancerMember http://{{.Address}}:{{.Port}}
{{end}} ProxySet lbmethod=bybusyness
</Proxy>
Redirect permanent /api/{{$tag}} /api/{{$tag}}/
ProxyPass /api/{{$tag}}/ balancer://{{$tag}}/
ProxyPassReverse /api/{{$tag}}/ balancer://{{$tag}}/
{{end}}
```

Save this file to disk at a place reachable by the Consul Template process like `/tmp/httpd.conf.ctmpl` and run Consul Template:

```shell
$ consul-template \
  -template="/tmp/httpd.conf.ctmpl:/etc/httpd/sites-available/balancer.conf"
```

Here is an example of what the file may render:

```text
# "frontend" api providers.
<Proxy balancer://frontend>
  BalancerMember http://104.131.109.106:8080
  BalancerMember http://104.131.109.113:8081
  ProxySet lbmethod=bybusyness
</Proxy>
Redirect permanent /api/frontend /api/frontend/
ProxyPass /api/frontend/ balancer://frontend/
ProxyPassReverse /api/frontend/ balancer://frontend/

# "api" api providers.
<Proxy balancer://api>
  BalancerMember http://104.131.108.11:8500
  ProxySet lbmethod=bybusyness
</Proxy>
Redirect permanent /api/api /api/api/
ProxyPass /api/api/ balancer://api/
ProxyPassReverse /api/api/ balancer://api/
```

- For a list of functions, please see the [Consul Template README](https://github.com/hashicorp/consul-template)
- For template syntax, please see [the golang text/template documentation](https://golang.org/pkg/text/template/)
