<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Elasticsearch Database Plugin — Design

## Scope

`elasticsearch-database-plugin` implements the OpenBao v5 database plugin
contract against the **native realm users API** of Elasticsearch 7+ and
OpenSearch. Talks HTTP/HTTPS directly with basic auth — no Elasticsearch
Go SDK dependency, so the plugin builds with `CGO_ENABLED=0` and stays
small. Also exposed remotely as `remote-elasticsearch-plugin`.

## Architecture

```
+------------------+      +----------------------+      +---------------+
|  OpenBao Core    | gRPC | elasticsearch-       | HTTP | Elasticsearch |
|  database mount  |----->| database-plugin      |----->| /_security/   |
+------------------+      +----------------------+      +---------------+
```

The plugin does **not** embed `connutil.SQLConnectionProducer` (ES isn't
SQL). It carries its own config + `http.Client` with TLS plumbing.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | `https://es:9200` |
| `username` / `password` | yes | Root credentials (typically `elastic`) |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `use_old_xpack` | no | Use ES 6's `/_xpack/security/` instead of `/_security/` |
| `username_template` | no | Override the dynamic-username template |

## Creation statements

A single JSON document:

```json
{
  "elasticsearch_roles": ["readonly", "kibana_user"],
  "full_name": "Read-only auditor",
  "email": "auditor@example.com",
  "metadata": {"managed_by": "openbao"}
}
```

- `elasticsearch_roles` (required) — array of pre-existing role names.
- `full_name`, `email`, `metadata` (optional) — sent through to the
  native users API.

## Lifecycle

### NewUser

1. Generate a username via the producer (default: 100-char hyphenated).
2. `PUT /_security/user/<name>` with `{password, roles, ...}`.

### UpdateUser

- Password: `POST /_security/user/<name>/_password`.
- Expiration: no-op (Elasticsearch has no native VALID UNTIL on users).

### DeleteUser

`DELETE /_security/user/<name>`. 404 is treated as success.

### Close

Closes idle HTTP connections.

## Path selection

When `use_old_xpack=true`, the plugin swaps `/_security/` for
`/_xpack/security/` for compatibility with Elasticsearch 6. Tested by
the fake-server unit test.

## Failure modes

| Scenario | Behavior |
| --- | --- |
| Empty `creation_statements` | `dbutil.ErrEmptyCreationStatement` |
| `elasticsearch_roles` empty | "elasticsearch_roles is required in creation_statements" |
| Non-JSON statement | "creation_statements must be a JSON role doc" |
| HTTP 4xx/5xx | Surface ES response body in the error |
| TLS verify failure | `tls_ca` / `tls_ca_path` parse errors surface during Initialize |

## Namespace support

Per-namespace mounts work without plugin-side changes.

## Tests

`elasticsearch_test.go` runs always-on tests against an `httptest.Server`:

- `TestES_TypeAndVersion`
- `TestES_StatementParsing`
- `TestES_FakeServer` — full Initialize / NewUser / UpdateUser / DeleteUser
  flow, asserting method + path on each request.
- `TestES_OldXPackPath` — verifies the legacy path swap.

The acceptance test is gated on `BAO_ACC=1` + `ES_URL`; see [TEST.md](TEST.md).
