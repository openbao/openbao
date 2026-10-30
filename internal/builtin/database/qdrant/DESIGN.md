<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Qdrant Database Plugin — Design

## Scope

`qdrant-database-plugin` is an OpenBao v5 database plugin for Qdrant.
It supports dynamic credential generation using Qdrant's Granular Access API
Keys (HS256-signed JSON Web Tokens) and stateful token revocation via the
`value_exists` claim:

- `Initialize` parses config and (with `VerifyConnection=true`) calls
  the `/readyz` endpoint with the configured admin API key as the `api-key`
  header.
- `NewUser` generates a unique dynamic username, ensures the validation
  collection (`openbao_users`) exists, inserts a validation point with
  `user_id`, parses creation statements into Qdrant collection access rules,
  and signs an HS256 JWT carrying the lease expiration (`exp`), permissions (`access`),
  and stateful validation claim (`value_exists`).
- `UpdateUser` validates requests but rejects password updates and static credentials since Qdrant does not support password-based user accounts.
- `DeleteUser` revokes the JWT immediately by deleting the validation point
  matching `user_id` from the validation collection in Qdrant.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | `http(s)://host:port` |
| `api_key` | yes | Admin API key used for JWT signing and verification |
| `validation_collection` | no | Collection used for stateful token validation (default: `openbao_users`) |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |

## Tests

Always-on tests cover Type/Version, `NewUser` JWT signing and claims verification,
`UpdateUser` validation, `ValueExists` lifecycle (`NewUser` point insertion + `DeleteUser` point deletion),
healthcheck against `httptest.Server`, and failure paths.
