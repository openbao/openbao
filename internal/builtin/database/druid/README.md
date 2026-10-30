<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Druid Database Plugin

Issues dynamic credentials against Apache Druid's BasicSecurity
authenticator/authorizer. Available as `druid-database-plugin` (built-in)
and `remote-druid-plugin` (proxied through a spoke).

See [DESIGN.md](DESIGN.md) and [TEST.md](TEST.md).

## Quick start

```bash
$ bao secrets enable database

$ bao write database/config/druid \
    plugin_name=druid-database-plugin \
    url=http://druid.example.com:8081 \
    username=admin password=admin \
    authenticator=MyBasicMetadataAuthenticator \
    authorizer=MyBasicMetadataAuthorizer \
    allowed_roles=reader

$ bao write database/roles/reader \
    db_name=druid \
    creation_statements='{"roles":["datasourceReadAccess"]}' \
    default_ttl=1h
```

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `plugin_name` | yes | `druid-database-plugin` or `remote-druid-plugin` |
| `url` | yes | Druid coordinator URL |
| `username` / `password` | yes | Root credentials |
| `authenticator` | no | Default `MyBasicMetadataAuthenticator` |
| `authorizer` | no | Default `MyBasicMetadataAuthorizer` |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Building

```
$ make druid-database-plugin
```

## License

Copyright &copy; AppsCode Inc.

Licensed under the [Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
