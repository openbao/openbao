Rendering PKI Certificates from Vault with Consul Template
----------------------------------------------------------
[Vault][vault] is a popular open source tool for managing secrets. In addition
to acting as an encrypted KV store, Vault can also generate dynamic secrets,
like PKI/TLS certificates.

When generating PKI certificates with Vault, the certificate, private key, and
any intermediate certs are all returned as part of the same API call. Most
software requires these files be placed in separate files on the system.

**Note:** In previous versions of consul-template [`generate_lease`][generate_lease] needed
to be set to `true` (non-default) on the Vault PKI role.  Without the lease the automatic
certificate renewal wouldn't work properly based on the expiration date of the certificate alone. 
As of v0.22.0 the certificate expiration details are now also used to monitor the renewal time
without needing an associated lease in Vault.  If you are issuing a very large number of certificates
there may be a performance advantage to not tracking every lease when leaving the default setting
of [`generate_lease`][generate_lease] set to `false`.

[vault]: https://www.vaultproject.io/ "Vault by HashiCorp"
[generate_lease]: https://www.vaultproject.io/api/secret/pki/index.html#generate_lease

## Multiple Output Files

Consul Template can run more than one template. At boot, all dependencies
(external API requests) are mapped into a single list. This means that multiple
templates watching the same path return the same data.

Consider the following three templates:

```liquid
{{- /* /tmp/cert.tpl */ -}}
{{ with secret "pki/issue/my-domain-dot-com" "common_name=foo.example.com" }}
{{ .Data.certificate }}{{ end }}
```

```liquid
{{- /* /tmp/ca.tpl */ -}}
{{ with secret "pki/issue/my-domain-dot-com" "common_name=foo.example.com" }}
{{ .Data.issuing_ca }}{{ end }}
```

```liquid
{{- /* /tmp/key.tpl */ -}}
{{ with secret "pki/issue/my-domain-dot-com" "common_name=foo.example.com" }}
{{ .Data.private_key }}{{ end }}
```

These are three different input templates, but when run under the same Consul
Template process, they are compressed into a single API call, sharing the
resulting data.

Here is an example Consul Template configuration:

```hcl
template {
  source      = "/tmp/cert.tpl"
  destination = "/opt/my-app/ssl/my-app.crt"
}

template {
  source      = "/tmp/ca.tpl"
  destination = "/opt/my-app/ssl/ca.crt"
}

template {
  source      = "/tmp/key.tpl"
  destination = "/opt/my-app/ssl/my-app.key"
}
```

To generate multiple certificates of the same path, use multiple Consul Template
processes.
