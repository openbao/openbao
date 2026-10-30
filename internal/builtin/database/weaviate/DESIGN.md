<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Weaviate Database Plugin — Design

## Scope

`weaviate-database-plugin` is an OpenBao v5 database plugin for Weaviate.
For Weaviate v1.30+ with `AUTHENTICATION_DB_USERS_ENABLED=true` and
`AUTHORIZATION_ENABLE_RBAC=true`, this plugin supports dynamic credentials
via Weaviate's User Management and RBAC REST APIs:

- `Initialize` parses config and (with `VerifyConnection=true`) calls
  `/v1/.well-known/ready` with the configured admin API key as a Bearer token.
- `NewUser` generates a unique username, creates the user via
  `POST /v1/users/db/{user_id}`, assigns roles configured in the role's
  creation statements via `POST /v1/authz/users/{id}/assign`, and returns
  Weaviate's generated API key in `NewUserResponse.Password`. Creation statements
  support structured JSON objects (`roles` and `custom_roles`), arrays of role names,
  or comma-separated strings.
- `UpdateUser` validates requests but rejects password updates and static credentials because server-generated API keys cannot be returned via the v5 update response.
- `DeleteUser` deletes the database user via `DELETE /v1/users/db/{user_id}`.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | `http(s)://host:8080` |
| `api_key` | yes | Admin API key for Weaviate RBAC API calls |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |

## Tests

Always-on tests cover Type/Version, `NewUser` user creation and role assignment,
`UpdateUser` validation, `DeleteUser`, healthcheck against `httptest.Server`,
and failure paths.
