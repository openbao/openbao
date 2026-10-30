<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Milvus Database Plugin — Design

## Scope

`milvus-database-plugin` implements the OpenBao v5 database plugin against
Milvus 2.x using the official Milvus Go SDK (`github.com/milvus-io/milvus-sdk-go/v2/client`)
over gRPC. Dynamic credentials become native Milvus users; `creation_statements`
is a JSON role doc listing pre-existing roles to grant.

Built-in and remote variants are both registered.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Milvus gRPC server address (e.g. `milvus:19530`) |
| `username` / `password` | one of | Root credentials |
| `token` | one of | API key / token (e.g. Zilliz Cloud) |
| `db_name` | no | Milvus database name |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Creation statement

`creation_statements` can be a JSON object specifying pre-existing roles and/or custom role definitions:

```json
{
  "roles": ["public"],
  "custom_roles": [
    {
      "name": "collection_reader",
      "privileges": [
        {
          "object_type": "Collection",
          "object_name": "Products",
          "privilege": "Search",
          "db_name": "default"
        }
      ]
    }
  ]
}
```

Aliases are supported:
- Custom roles: `custom_roles` or `customRoles`.
- Role definitions: `privileges` or `permissions`.
- Privileges: `object_type` / `objectType` / `type`, `object_name` / `objectName` / `object` / `collection`, `privilege` / `action` / `permission`, `db_name` / `dbName` / `database`.
- Object types: `Collection`, `Global` (default if object is `*` or empty), `User`.

Single custom role JSON objects, JSON arrays, and comma-separated role name strings are also supported.

## Lifecycle

### NewUser

- Ensures custom roles exist via `client.CreateRole(ctx, role.Name)` and grants their privileges via `client.Grant(ctx, ...)`.
- Calls `client.CreateCredential(ctx, username, password)`.
- For each role in `creation_statements`, calls `client.AddUserRole(ctx, username, role)`.
- If `AddUserRole` fails, the plugin calls `client.DeleteCredential(ctx, username)` to clean up the partially created user.

### UpdateUser

- No-op. Milvus requires the user's old password to rotate credentials unless `common.security.superUsers` is configured. Because OpenBao does not retain previously-generated dynamic passwords, `UpdateUser` returns success without modifying credentials to prevent rotation errors.

### DeleteUser

- Calls `client.DeleteCredential(ctx, username)`.

## Tests

Always-on unit tests run against an in-memory gRPC server implementing `milvuspb.MilvusServiceServer` (`fakeMilvusServer`).
Tests cover:
- Type and version reporting
- Statement JSON parsing with custom roles and aliases
- Full credential lifecycle (`CreateCredential`, `AddUserRole`, no-op `UpdateCredential`, `DeleteCredential`)
- Custom roles creation and privilege grants
- Validation and error handling
- Role grant failure and automatic cleanup of partially created credentials

Acceptance tests are gated on `BAO_ACC=1` + `MILVUS_URL`.
