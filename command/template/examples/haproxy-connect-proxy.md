# HAProxy as a Consul Connect ingress proxy

You can use HAProxy to proxy into a Consul Connect service mesh without a
sidecar by fetching the required certificates using Consul-Template. This guide
is based off the introductory [Connect Services - Service Mesh Learn
guide][mesh] and, like it, reviews a simple example you can run locally. Please
see the [mesh][mesh] introductory guide for more details as this guide will
just run through the basics to get the example running.

### Security/Techincal Note

This guide is only meant to demonstrate features and many things have been
simplified, it is not a production ready or secure deployment.

To follow this guide you'll need HAProxy, a web-server, Consul and
Consul-template installed. Additionally the shell script requires some standard
Unix CLI tools as well as GNU Screen.

Each of the services below will run in the foreground and output its logs to
that console. They are designed to all run from files in the same directory.

For convenience, you can find a shell script to extract the configuration files
and run the commands the from this document in the haproxy-connect-proxy/
sub-directory. The script should be a handy reference even if you don't want to
run it directly.

## Start Consul Agent with the Services Configured

Start the consul agent in dev mode using the configuration file below for the
'webserver' and 'ingress' services.

```shell
$ consul agent -dev -log-level=info -config-file=consul-services.json
```

#### consul-services.json

This contains the service definitions for both the `webserver` and the
`ingress` proxy (below). The names used are important as those are how you will
refer to them later.

```hcl
cat > consul-services.json << EOF
{
  "services": [
    {
      "name": "ingress",
      "port": 8080
    },
    {
      "name": "webserver",
      "connect": { "sidecar_service": {} },
      "port": 8000
    }
  ]
}
EOF
```

## Start the Webserver (a Connect-unaware Service)

First, you need a web server to proxy to and for that we'll just use the simple
http server included with Python as you probably already have it installed. By
default it listens on port 8000 and will publish an `index.html` if found.

```shell
$ python -m SimpleHTTPServer
```
### Use a Sidecar to add it to the Connect mesh network

Then start the sidecar for the `webserver` service.

```shell
$ consul connect proxy -sidecar-for webserver
```

**Note**: the argument to `-sidecar-for` needs to match the name registered
with consul in the `consul-services.json` config file above.

#### index.html
And some content to serve.
```html
cat > index.html << EOF
Brought to you by HAProxy!
EOF
```

## HAProxy Ingress Proxy to Web-Server via Mesh Sidecar

Now that you have a web-server running, registered with Consul with a sidecar
proxy running, you can run an HAProxy proxy that will route traffic directly to
the web-server's sidecar via the encrypted mesh network.

To connect to the mesh network you will need the required TLS certificates,
the root certificate (the CA) and the client certificates. HAProxy likes the CA cert in one file and both the client certs in another.

#### ca.crt
```liquid
cat > ca.crt.tmpl << EOF
{{range caRoots}}{{.RootCertPEM}}{{end}}
EOF
```
#### certs.pem
```liquid
cat > certs.pem.tmpl << EOF
{{with caLeaf "ingress"}}{{.PrivateKeyPEM}}{{.CertPEM}}{{end}}
EOF
```

With all the certificate templates in place, you now just need the
configuration file template for the HAProxy proxy, it uses the `connect`
template function to get all the "webserver" connect enabled services.

#### haproxy.conf.tmpl
```haproxy
cat > haproxy.conf.tmpl << EOF
defaults
	mode	http
    timeout connect 5000
    timeout client  50000
    timeout server  50000

backend connect
{{range connect "webserver"}}
    server webserver {{.Address}}:{{.Port}} ssl verify required ca-file ./ca.crt crt ./certs.pem
{{end}}

frontend app
    bind *:8080
    default_backend connect
EOF
```

For more on the details of the HAProxy configuration file, please see the
[HAProxy documentation][haproxy].


## Running the HAProxy Ingress Proxy with Consul-Template

Using the consul-template configuration below, run the HAProxy proxy.

```shell
$ consul-template -config ingress-config.hcl -log-level=info
```

Consul-template will restart the HAProxy server when any of the templates are
rendered (files written). Note that if multiple templates are rendered, it will
still only restart it once.

#### ingress-config.hcl
```hcl
cat > ingress-config.hcl << EOF
exec {
  command = "/usr/sbin/haproxy -f haproxy.conf"
}
template {
  source = "ca.crt.tmpl"
  destination = "ca.crt"
}
template {
  source = "certs.pem.tmpl"
  destination = "certs.pem"
}
template {
  source = "haproxy.conf.tmpl"
  destination = "haproxy.conf"
}
EOF
```

## Test it
```shell
$ curl http://localhost:8080
Brought to you by HAProxy!
```

## Intentions Work

Since the ingress service was registered with Consul, you can control what
services it is able to connect to within the mesh network using
[intentions][intentions]. Note that you refer to the services using the names
registered with consul above.

```shell
$ curl http://localhost:8080
Brought to you by HAProxy!

$ consul intention create -deny ingress webserver
Created: ingress => webserver (deny)

$ curl http://localhost:8080
<html><body><h1>503 Service Unavailable</h1>
No server is available to handle this request.
</body></html>

$ consul intention delete ingress webserver
Intention deleted.

$ curl http://localhost:8080
Brought to you by HAProxy!
```

## Using the shell script

Included is a shell script that will extract the config files from this
document and runs all the different services in multiple [GNU Screen][screen]
windows. The script provides some basic instructions on using Screen.

```shell
$ cd examples/nginx-connect-proxy/
$ ./run-nginx-connect-proxy
...
```

[mesh]: https://learn.hashicorp.com/consul/getting-started/connect
[haproxy]: http://cbonte.github.io/haproxy-dconv/1.8/configuration.html
[intentions]: https://www.consul.io/docs/connect/intentions.html
[screen]: https://www.gnu.org/software/screen/
