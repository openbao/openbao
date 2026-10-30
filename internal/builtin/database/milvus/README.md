<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Milvus Database Plugin

Issues dynamic credentials against Milvus 2.x via the Milvus Go SDK (v2)
over gRPC. Available as `milvus-database-plugin` (built-in) and
`remote-milvus-plugin` (proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/milvus \
    plugin_name=milvus-database-plugin \
    url=milvus.example.com:19530 \
    username=root password=Milvus123 \
    allowed_roles=reader

$ bao write database/roles/reader \
    db_name=milvus \
    creation_statements='{"roles":["public"]}' \
    default_ttl=1h
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `milvus-database-plugin` or `remote-milvus-plugin` |
| `url` | yes | Milvus gRPC server address (`host:port`) |
| `username` / `password` | one of | Root credentials |
| `token` | one of | API key / token (e.g. Zilliz Cloud) |
| `db_name` | no | Default database name |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Building

```
$ make milvus-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
