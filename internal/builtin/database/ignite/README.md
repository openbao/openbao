<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Ignite Database Plugin

Issues dynamic credentials against Apache Ignite via the thin client
binary protocol and native SQL `CREATE USER` DDL. Available as
`ignite-database-plugin` (built-in) and `remote-ignite-plugin`
(proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

Requires Ignite 2.5+, persistence enabled, and
`authenticationEnabled=true` on the cluster's IgniteConfiguration.

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/ignite \
    plugin_name=ignite-database-plugin \
    url=tcp://ignite.example.com:10800 \
    username=ignite password=ignite \
    allowed_roles=reader

$ bao write database/roles/reader \
    db_name=ignite \
    creation_statements='CREATE USER "{{name}}" WITH PASSWORD '"'"'{{password}}'"'"';' \
    default_ttl=1h
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `ignite-database-plugin` or `remote-ignite-plugin` |
| `url` | yes* | Thin client target; only host/port are used (e.g. `tcp://ignite:10800`) |
| `host` / `port` | no | Explicit override of `url`; port defaults to 10800 |
| `username` / `password` | yes | Root credentials |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Identifier / password constraints

- Usernames are uppercased and underscore-separated by the producer.
  Custom templates that emit forbidden characters (`"`, `'`, `;`, `` ` ``)
  are rejected at runtime.
- Passwords containing single quotes are rejected up front — Ignite DDL
  has no way to escape them safely.

## Building

```
$ make ignite-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
