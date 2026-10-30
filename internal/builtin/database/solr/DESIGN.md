<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Solr Database Plugin — Design

## Scope

`solr-database-plugin` implements the OpenBao v5 database plugin contract
against Apache Solr using the Security Plugin API:

- `admin/authentication` — Basic Auth Plugin user table.
- `admin/authorization` — Rule-Based Authorization Plugin role bindings.

Dynamic credentials become entries in `security.json` under the BasicAuth
user list. `creation_statements` is a JSON role document
`{"roles":["admin","reader"]}` listing pre-existing roles to bind.

Exposed both as `solr-database-plugin` and `remote-solr-plugin`.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Solr base URL (e.g. `http://solr:8983/solr`) |
| `username` / `password` | yes | Root credentials |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Lifecycle

### NewUser

```http
POST /solr/admin/authentication
{"set-user": {"<name>": "<password>"}}

POST /solr/admin/authorization
{"set-user-role": {"<name>": ["admin","reader"]}}
```

If the second call fails, the plugin posts `{"delete-user":["<name>"]}` to
clean up the half-configured user before returning the error.

### UpdateUser

Re-POST `set-user` with the new password.

### DeleteUser

POST `{"delete-user":["<name>"]}`. Solr's response on a missing user is
still 200, so the operation is naturally idempotent.

## Failure modes

| Scenario | Behavior |
| --- | --- |
| Empty `creation_statements` | `dbutil.ErrEmptyCreationStatement` |
| Non-JSON `creation_statements` | "creation_statements must be a JSON role doc" |
| `set-user-role` HTTP error | Plugin deletes the user and returns the error |
| Wrong base URL (missing `/solr`) | Initialize ping fails with the upstream's 404 body |

## Tests

Always-on tests against `httptest.Server`:

- `Type` / `PluginVersion`
- JSON role-doc parsing
- Full NewUser → UpdateUser → DeleteUser flow, asserting the path and
  method of each request.

Acceptance tests are gated on `BAO_ACC=1` + `SOLR_URL`.
