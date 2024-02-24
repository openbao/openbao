nginx Consul Template Example
-----------------------------
nginx is popular open source web server, reverse proxy, and load balancer. You can read more about nginx's configuration file syntax in the [nginx documentation](https://nginx.org/en/docs/).

## Global Load Balancer
Here is an example template for rendering an nginx configuration file with Consul Template:

```liquid
{{range services}} {{$name := .Name}} {{$service := service .Name}}
upstream {{$name}} {
  zone upstream-{{$name}} 64k;
  {{range $service}}server {{.Address}}:{{.Port}} max_fails=3 fail_timeout=60 weight=1;
  {{else}}server 127.0.0.1:65535; # force a 502{{end}}
} {{end}}

server {
  listen 80 default_server;

  location / {
    root /usr/share/nginx/html/;
    index index.html;
  }

  location /stub_status {
    stub_status;
  }

{{range services}} {{$name := .Name}}
  location /{{$name}} {
    proxy_pass http://{{$name}};
  }
{{end}}
}
```

Save this file to disk at a place reachable by the Consul Template process like `/tmp/nginx.conf.ctmpl` and run Consul Template:


```shell
$ consul-template \
  -template="/tmp/nginx.conf.ctmpl:/etc/nginx/conf.d/default.conf"
```

You should see output similar to the following:

```text
upstream service {
  zone upstream-service 64k;
  least_conn;
  server 172.17.0.3:80 max_fails=3 fail_timeout=60 weight=1;
}

server {
  listen 80 default_server;

  location / {
    root /usr/share/nginx/html/;
    index index.html;
  }

  location /stub_status {
    stub_status;
  }

  location /service {
    proxy_pass http://service;
  }
}
```

- For a list of functions, please see the [Consul Template README](https://github.com/hashicorp/consul-template)
- For template syntax, please see [the golang text/template documentation](https://golang.org/pkg/text/template/)
