<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Druid Database Plugin — Design

## Scope

`druid-database-plugin` implements the OpenBao v5 database plugin
contract against Apache Druid's BasicSecurity Coordinator API. Dynamic
credentials become entries in the configured `authenticator` (with a
password set via `/credentials`) and role bindings in the configured
`authorizer`.

Built-in and remote variants are both registered (`druid-database-plugin`
and `remote-druid-plugin`).

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Druid coordinator URL (e.g. `http://druid:8081`) |
| `username` / `password` | yes | Root credentials |
| `authenticator` | no | Default `MyBasicMetadataAuthenticator` |
| `authorizer` | no | Default `MyBasicMetadataAuthorizer` |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Creation statement

```json
{"roles": ["datasourceReadAccess", "viewer"]}
```

Roles must already exist on the cluster's authorizer.

## Lifecycle

### NewUser

```http
POST /druid-ext/basic-security/authentication/db/<authenticator>/users/<name>
POST /druid-ext/basic-security/authentication/db/<authenticator>/users/<name>/credentials   {"password":"…"}
POST /druid-ext/basic-security/authorization/db/<authorizer>/users/<name>
POST /druid-ext/basic-security/authorization/db/<authorizer>/users/<name>/roles/<role>      (per role)
```

If any of the credential / authorizer / role calls fails, the plugin
sends DELETE on the authenticator user so we don't leak a partial
configuration.

### UpdateUser

POST `/credentials` with the new password against the authenticator.

### DeleteUser

DELETE both the authorizer and authenticator user records. 404 is fine
on either side.

## Tests

`druid_test.go` covers:

- Type / PluginVersion
- JSON statement parsing
- Default authenticator/authorizer when unspecified
- Full Initialize → NewUser → UpdateUser → DeleteUser flow against
  `httptest.Server`, asserting the path of each request.

Acceptance tests are gated on `BAO_ACC=1` + `DRUID_URL`.
