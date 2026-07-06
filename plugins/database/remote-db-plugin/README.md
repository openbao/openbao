<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Remote Database Plugin

A hub-and-spoke deployment of OpenBao's database secrets engine. One OpenBao
instance (**the hub**) brokers credential operations over mTLS gRPC to one or
more `bao relay run` daemons (**the spokes**) that run the actual built-in
database plugins in-process against locally-reachable databases.

See [DESIGN.md](DESIGN.md) for the architecture, wire protocol, trust
bootstrap, and request lifecycle. [TEST.md](TEST.md) walks through every
manual scenario in the PR's test plan (smoke, token security, CSR
validation, renewal, CA rotation, failure modes, concurrency). This file is
the operator quick start.

## Quick start

```bash
# --- on the hub -----------------------------------------------------------

# 1. Initialize the hub: spoke-CA, hub TLS identity, bootstrap token, and
#    the proxy gRPC listener (on the port you advertise to spokes).
$ bao relay init \
    -hub-endpoint=hub.example.com:50053 \
    -hub-dns-sans=hub.example.com \
    -allowed-spoke-name=spoke-1 \
    -token-ttl=1h

# `bao relay init` prints a ready-to-paste join command, for example:
#
#   bao relay join \
#       -hub-addr=hub.example.com:50053 \
#       -hub-cert-hash=sha256:abcd... \
#       -token=a6b2fa.fd41cda24adcb696 \
#       -spoke-name=spoke-1

# --- on each spoke --------------------------------------------------------

# 2. Exchange the bootstrap token for a long-lived mTLS client cert.
$ bao relay join \
    -address=https://hub.example.com:8200 \
    -hub-addr=hub.example.com:50053 \
    -hub-cert-hash=sha256:abcd... \
    -token=a6b2fa.fd41cda24adcb696 \
    -spoke-name=spoke-1 \
    -credentials-dir=/etc/openbao-spoke

# 3. Run the spoke daemon (long-running).
$ bao relay run \
    -server=hub.example.com:50053 \
    -credentials-dir=/etc/openbao-spoke

# --- on the hub, day-2 ----------------------------------------------------

# 4. Confirm the spoke is connected and healthy.
$ bao relay list
Listener: :50053
Connected: 1 total, 1 healthy (stale after 45s)

NAME       LAST SEEN  UPTIME  CERT EXP  HEALTH
spoke-1    0s ago     5s      29d       OK

# 5. Mount the database engine and point it at the spoke via the proxy plugin.
$ bao secrets enable database
$ bao write database/config/spoke-pg \
    plugin_name=remote-postgres-plugin \
    spoke_name=spoke-1 \
    connection_url='postgresql://{{username}}:{{password}}@postgres:5432/postgres' \
    username=postgres \
    password=secret \
    allowed_roles='*'

$ bao write database/roles/readonly \
    db_name=spoke-pg \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
    default_ttl=1h

$ bao read database/creds/readonly
```

## CLI surface

| Command | Side | What it does |
| --- | --- | --- |
| `bao relay init` | hub | Generate the spoke-CA + hub TLS cert, create a bootstrap token, start the proxy gRPC listener, print the join command. |
| `bao relay join` | spoke | Fetch + JWS-verify cluster-info, pin the CA via SPKI hash, exchange the token for a client cert. Writes credentials to `-credentials-dir`. Refuses to overwrite an existing directory without `-force`. |
| `bao relay run` | spoke | Long-running daemon. Connects to the hub with mTLS, serves DB plugin requests in-process, auto-renews its own cert, and evicts idle cached plugin instances. |
| `bao relay renew` | spoke | One-shot manual renewal. Reuses the existing cert to authenticate. |
| `bao relay list` | hub | Connected spokes with last-seen, health, and client-cert expiry (`CERT EXP`). `bao read relay/spokes` exposes the same as `cert_not_after` (Unix seconds) per spoke. |
| `bao relay ca status` | hub | CA + hub cert metadata: subjects, expiry (with relative time), SANs, listener port. Honors `-format=json|yaml` for machine consumption. |
| `bao relay ca rotate` | hub | Default: re-issue the hub TLS cert from the existing CA (transparent to spokes). With `-full -yes`: rotate the CA itself (every spoke must re-join). |
| `bao write relay/ca/update-endpoint` | hub | Change advertised endpoint or hub TLS SANs without rotating the CA. `hub_dns_sans` / `hub_ip_sans` accept either a comma-separated value or repeated key=value pairs. Bound listener port can't change here. |
| `bao relay token create` | hub | Issue a fresh bootstrap token; honors `-ttl`, `-allowed-spoke-name`. Prints a prominent stderr warning that the token is shown only once. |
| `bao relay token list` | hub | Outstanding bootstrap tokens with expiry. |
| `bao relay token revoke` | hub | Revoke by token id. |

## Supported databases

| Plugin name | Backed by |
| --- | --- |
| `remote-postgres-plugin` | OpenBao's built-in `postgresql-database-plugin` |
| `remote-mysql-plugin` | `mysql-database-plugin` |
| `remote-redis-plugin` | `valkey-database-plugin` (redis-compatible) |
| `remote-valkey-plugin` | `valkey-database-plugin` |
| `remote-cassandra-plugin` | `cassandra-database-plugin` |
| `remote-influxdb-plugin` | `influxdb-database-plugin` |

Adding more is one line in `helper/builtinplugins/registry.go` plus a `case`
in `runner/runner.go:loadPlugin` — the underlying plugin already runs
in-process on the spoke.

## Binaries

| Binary | Role | Location |
| --- | --- | --- |
| `bao` | OpenBao server + the `bao relay ...` CLI subtree | Hub cluster |
| `bao relay run` | The long-running spoke daemon (same `bao` binary, different subcommand) | Spoke cluster |

Operators only install one binary everywhere.

## File structure

```
plugins/database/remote-db-plugin/
├── proxy.go               # Hub-side proxy plugin (PluginProxy) + proxy gRPC server
├── bootstrap/             # Trust-bootstrap primitives
│   ├── token.go           #   <id>.<secret> format + detached JWS-HS256
│   ├── pubkeypin.go       #   SPKI SHA-256 hash + verification
│   ├── ca.go              #   Spoke-CA gen + CSR signing
│   └── state.go           #   Process-wide identity singleton
├── runner/                # Spoke-side in-process plugin dispatcher
│   └── runner.go          #   Per-instance plugin cache + dispatch
├── proto/                 # gRPC contract
│   ├── agent.proto
│   └── gen/               # protoc-generated stubs
├── yaml/                  # KubeVault deployment manifests
├── Dockerfile.spoke       # Spoke image (re-uses the bao binary)
├── DESIGN.md              # Architecture, wire protocol, request lifecycle
└── README.md              # This file
```

The CLI lives under `command/relay_*.go` and the `relay/` logical backend
lives under `builtin/logical/relay/`.

## Security

The trust bootstrap is a port of kubeadm's discovery flow. See
[DESIGN.md](DESIGN.md) for the full threat model. Highlights:

- **mTLS** between hub and spoke, **TLS 1.3 floor** on both sides. Spoke
  identity comes from the verified client cert CN, not from any wire field.
  `bao relay run` verifies its local cert chains to the bundled `ca.pem`
  at startup — a half-rotated credentials directory fails fast with a
  clear error instead of an opaque TLS handshake later — mirroring the
  hub's chain-check on `SetIdentity`.
- **Bootstrap tokens** in seal-wrapped storage. JWS-HS256 over the
  cluster-info bundle authenticates the hub to a joining spoke before TLS is
  established. All token-related `sign-csr` failures collapse to the same
  generic error so a holder of one valid token cannot probe other token
  ids; real reasons land in the server log. The token check evaluates
  every per-field test (secret, expiry, usage, allowed_spoke_name) against
  a placeholder when the id is unknown, so "unknown id" pays the same HMAC
  cost as "wrong secret" — closing a timing oracle that would otherwise
  let a valid-token holder enumerate live ids.
- **CA-cert SPKI pin** is printed by `bao relay init` and verified by
  `bao relay join` with a constant-time compare — defense in depth on top
  of the JWS check.
- **Strict CSR validation** on both initial-issue and renew: ECDSA or RSA
  ≥ 2048 only, no SANs, no extra X.509 extensions, reserved CNs
  (`openbao-hub`, `openbao-spoke-ca`) refused.
- **gRPC HTTP/2 keepalive + app-level heartbeats** so a wedged spoke is
  detected within ~45s; `bao relay list` surfaces both.
- **Graceful shutdown**: `bao relay run` on SIGINT/SIGTERM drains in-flight
  workers, cancels timers, flushes the send channel, and closes every
  cached DB connection cleanly before exiting.

## Status & known limitations

- Spoke certs renew automatically: `bao relay run` ticks every
  `-renew-check-every` (default 1h) and submits a new CSR via the existing
  mTLS connection when the cert is past `-renew-threshold` (default 0.5).
  Operators can also force `bao relay renew` directly. The hub rejects any
  CSR whose CN does not match the calling spoke's peer-cert CN, so renewal
  cannot rebind to a different identity. The hub records each spoke's current
  client-cert `NotAfter` (captured at connect, refreshed in place on renewal)
  and exposes it via `bao relay list` / `relay/spokes` `cert_not_after`.
- See DESIGN.md "Failure modes" for the rest.

## License

Copyright &copy; AppsCode Inc.

Licensed under the
[Mozilla Public License, v. 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
