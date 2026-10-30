<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Kafka Database Plugin

Issues dynamic SCRAM-SHA-256/512 credentials against Apache Kafka using
the AdminClient API. Available as `kafka-database-plugin` (built-in) and
`remote-kafka-plugin` (proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/kafka \
    plugin_name=kafka-database-plugin \
    brokers=broker1.example.com:9092,broker2.example.com:9092 \
    username=admin password=admin \
    mechanism=SCRAM-SHA-256 \
    allowed_roles=producer

$ bao write database/roles/producer \
    db_name=kafka \
    creation_statements='{"mechanism":"SCRAM-SHA-256","iterations":4096}' \
    default_ttl=1h
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `kafka-database-plugin` or `remote-kafka-plugin` |
| `brokers` | yes | Bootstrap brokers |
| `username` / `password` | yes | Root credentials |
| `mechanism` | no | `SCRAM-SHA-256` (default) or `SCRAM-SHA-512` |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## ACLs

ACL provisioning is **not implemented** in this plugin. Configure ACLs
via `kafka-acls.sh` (or the equivalent AdminClient call from your
deployment tooling) against the username this plugin returns.

## Building

```
$ make kafka-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
