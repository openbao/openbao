<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Ignite Database Plugin — Design

## Scope

`ignite-database-plugin` implements the OpenBao v5 database plugin
against Apache Ignite using the thin client binary protocol (default
port 10800). Dynamic credentials become native SQL users via
`CREATE USER` / `ALTER USER` / `DROP USER` DDL, which Ignite 2.5+
supports when persistence is enabled and `authenticationEnabled=true`
is set on the cluster.

Built-in and remote variants are both registered.

## Why the thin client?

Apache Ignite has no official Go driver. The community
`amsokol/ignite-go-client` is unmaintained but implements the binary
client protocol we need (connect + auth + TLS + SQL fields query), and
it is the same library KubeDB's `db-client-go` uses, so behaviour is
consistent across the stack. An earlier revision of this plugin drove
the HTTP REST API (`cmd=qryfldexe`, port 8080) instead; that approach
was dropped because the REST endpoint requires a real cache to execute
against and lives on a different port than the thin client every other
consumer uses.

Statements run through `OP_QUERY_SQL_FIELDS` with no bound cache
(cache id 0) and schema `PUBLIC`, so user-management DDL works on a
cluster with no user-created caches.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes* | Thin client target; only host and port are used (e.g. `tcp://ignite:10800`). Accepted for compatibility with configs written for the REST-based plugin. |
| `host` / `port` | no | Explicit override of what `url` provides; port defaults to 10800 |
| `username` / `password` | yes | Root credentials (sent during the binary handshake) |
| `tls_ca` / `tls_certificate` / `tls_key` / `tls_server_name` / `tls_skip_verify` / `use_tls` | no | Inline TLS settings (`internal/helper/dbtlsutil`). `ca_cert`, `client_cert`, `client_key` and `insecure` are accepted as aliases. |
| `username_template` | no | Override default template |
| `spoke_name` | yes (remote) | Spoke that executes the requests |

## Identifier and password safety

Ignite DDL doesn't take parameters, so the plugin builds SQL strings
directly. Before doing so it validates both sides:

- **`safeIdentifier`** rejects any identifier containing `"`, `'`, `;`,
  or `` ` ``.
- **`safePassword`** rejects passwords containing a single quote (which
  would terminate the string literal).

The username producer additionally uppercases and underscore-converts the
generated name, so the result is always inside the safe character set.

## Creation statement

Templated SQL — same conventions as the SQL plugins:

```sql
CREATE USER "{{name}}" WITH PASSWORD '{{password}}';
```

Operators can supply multiple statements separated by `;`. Each is run
sequentially over its own thin client connection. Per-statement failures
are surfaced verbatim.

## Lifecycle

- **NewUser** — render and execute each creation statement.
- **UpdateUser** — `ALTER USER "<name>" WITH PASSWORD '<pw>'`.
- **DeleteUser** — `DROP USER "<name>"`, or custom revocation statements.
- **Expiration** — no-op (Ignite has no `VALID UNTIL`).

Connections are opened per operation and closed afterwards: credential
operations are infrequent, so this keeps reconnect handling trivial at
the cost of one extra handshake per call.

## Tests

Always-on tests cover Type/Version, identifier validation, password
validation, the template renderer, host/port normalization (including
backwards-compatible `url` parsing), and config validation.

Acceptance tests run against a real cluster and are gated on
`BAO_ACC=1` + `IGNITE_ADDR` (host:port of the thin client listener),
plus optional `IGNITE_CA_CERT` / `IGNITE_INSECURE`.
