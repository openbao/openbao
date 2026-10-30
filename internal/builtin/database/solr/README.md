<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Solr Database Plugin

Issues dynamic Solr Basic Auth users via the Security Plugin API.
Available as `solr-database-plugin` (built-in) and `remote-solr-plugin`
(proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/solr \
    plugin_name=solr-database-plugin \
    url=http://solr.example.com:8983/solr \
    username=solr password=SolrRocks \
    allowed_roles=reader

$ bao write database/roles/reader \
    db_name=solr \
    creation_statements='{"roles":["read-only"]}' \
    default_ttl=1h
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `solr-database-plugin` or `remote-solr-plugin` |
| `url` | yes | Solr base URL including the `/solr` path |
| `username` / `password` | yes | Root credentials |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Creation statement

```json
{"roles": ["admin", "reader"]}
```

Roles must already exist on the cluster's Authorization Plugin config.

## Building

```
$ make solr-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
