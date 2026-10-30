<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Elasticsearch Database Plugin

Issues dynamic credentials against Elasticsearch / OpenSearch via the
native realm users API. Available as `elasticsearch-database-plugin` (built
in) and `remote-elasticsearch-plugin` (proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/es \
    plugin_name=elasticsearch-database-plugin \
    url=https://es.example.com:9200 \
    username=elastic password=changeme \
    allowed_roles='reader'

$ bao write database/roles/reader \
    db_name=es \
    creation_statements='{"elasticsearch_roles":["readonly"]}' \
    default_ttl=1h max_ttl=24h

$ bao read database/creds/reader
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `elasticsearch-database-plugin` or `remote-elasticsearch-plugin` |
| `url` | yes | Full URL with scheme + port |
| `username` / `password` | yes | Root credentials |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `use_old_xpack` | no | Use ES 6 `/_xpack/security/` path |
| `username_template` | no | Override the dynamic-username template |
| `spoke_name` | yes (remote) | Spoke that will execute the requests |

## Creation statement

JSON role document with `elasticsearch_roles` plus optional `full_name`,
`email`, `metadata`. Roles must already exist on the cluster.

```json
{"elasticsearch_roles":["readonly","kibana_user"],"full_name":"Bao Reader"}
```

## Remote variant

```bash
$ bao write database/config/spoke-es \
    plugin_name=remote-elasticsearch-plugin \
    spoke_name=spoke-1 \
    url=https://es.spoke.local:9200 \
    username=elastic password=changeme \
    allowed_roles='*'
```

## Building

```
$ make elasticsearch-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
