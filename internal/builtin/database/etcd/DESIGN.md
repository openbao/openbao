<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# etcd Database Plugin — Design

## Scope

`etcd-database-plugin` implements the OpenBao v5 database plugin contract
against etcd's built-in v3 Auth API, using the official
`go.etcd.io/etcd/client/v3` client. Dynamic credentials become native etcd
users created via `UserAdd`; permissions come from pre-existing roles and/or
inline custom roles defined in `creation_statements`.

Also exposed remotely as `remote-etcd-plugin`.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `endpoints` | yes | Comma-separated list of etcd client URLs, e.g. `https://etcd1:2379,https://etcd2:2379` |
| `username` / `password` | yes if auth is enabled | Root credentials used to authenticate the client |
| `dial_timeout` | no | Go duration string; defaults to `5s` |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

`endpoints` accepts either a native array or a single comma-separated string
(the latter is split manually since the generic connection-config path
schema doesn't know about plugin-specific list fields — see `kafka`'s
`brokers` field for the same pattern).

## Creation statement

Accepts existing roles, custom inline roles, or a combination:

```json
{
  "roles": ["reader"],
  "custom_roles": [
    {
      "name": "app_writer",
      "permissions": [
        {
          "permission": "readwrite",
          "key": "/app/",
          "prefix": true
        },
        {
          "permission": "read",
          "key": "/config/sample"
        }
      ]
    }
  ]
}
```

Pre-existing roles named under `roles` must already exist on the cluster. Custom roles named under `custom_roles` are created if necessary, and their listed permissions are granted or updated by the plugin.

Custom-role management is deliberately additive-only. The plugin does not
revoke permissions that disappear from a later definition and does not delete
custom roles. A permission update replaces the permission type only when the
key and range are unchanged; changing either adds another permission while the
old range remains. Operators must revoke obsolete permissions directly in etcd
or migrate to a uniquely named role before retiring the old one. Reusing a
custom-role name across OpenBao roles intentionally produces the union of their
permissions.

## Lifecycle

### NewUser

```
ensureRole(customRole)      // RoleAdd (ignoring "already exists") + RoleGrantPermission
UserAdd(name, password)
UserGrantRole(name, role)   // once per role in the statement
```

1. If custom roles are defined, each is created via `RoleAdd`. If the role already exists, creation continues without error. Each permission is then granted or updated via `RoleGrantPermission`; existing permissions not present in the statement remain unchanged.
2. The user is created via `UserAdd`.
3. Each role (pre-existing and custom) is granted to the user via `UserGrantRole`.
4. On any per-role grant failure, the plugin calls `UserDelete` before returning so a half-configured user isn't left behind. Custom roles created in step 1 are not deleted.

### UpdateUser

```
UserChangePassword(name, newPassword)
```

Expiration is a no-op (etcd has no native credential-expiry concept on
users).

### DeleteUser

```
UserDelete(name)
```

`DeleteUser` only removes the ephemeral user. Custom roles are not deleted because other active credentials may still be bound to them. A "user name not found" error is treated as success so revocation is idempotent against a user that's already gone.

## Connectivity check

`Initialize` with `verify_connection=true` calls `AuthStatus`, which reaches
a live etcd member without requiring any particular permission. Bad root
credentials still surface here: the client library authenticates lazily via
an interceptor on the first RPC that needs a token, so a failing
`Authenticate` call propagates as the `AuthStatus` error.

## Namespace support

Per-namespace mounts work without plugin-side changes.

## Failure modes

| Scenario | Behavior |
| --- | --- |
| Empty `creation_statements` | `dbutil.ErrEmptyCreationStatement` |
| Role does not exist | `UserGrantRole` fails; plugin deletes the user and returns the error |
| `endpoints` missing | "endpoints is required" |
| Invalid `dial_timeout` | "invalid dial_timeout: ..." |
| `DeleteUser` on an already-gone user | Treated as success (idempotent) |

## Tests

Always-on:

- `Type` / `PluginVersion`
- `sanitizeEndpoints` / `hostFromEndpoint` helpers
- `isUserNotFound` helper
- Statement parsing
- `Initialize` validation (missing endpoints, bad dial_timeout, incomplete TLS identity)
- `UpdateUser` / `DeleteUser` validation
- Not-initialized error paths

Acceptance tests are gated on `BAO_ACC=1` + `ETCD_ENDPOINTS`.
