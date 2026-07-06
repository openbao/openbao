<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Test plan — remote-db-plugin

A detailed walk-through for exercising every behaviour the
[DESIGN.md](DESIGN.md) and [README.md](README.md) commit to. Some checks are
automated (Go unit tests); the rest are manual scenarios you can run against
a dev hub + a single spoke + one real PostgreSQL.

The flow is roughly:

1. [Prerequisites](#prerequisites)
2. [Automated unit tests](#automated-unit-tests)
3. [Bring up the test environment](#bring-up-the-test-environment)
4. [Smoke: init → join → run → credentials](#smoke-init--join--run--credentials)
5. [Token security](#token-security)
6. [CSR validation](#csr-validation)
7. [Renewal](#renewal)
8. [CA management](#ca-management)
9. [Failure modes](#failure-modes)
10. [Concurrency](#concurrency)
11. [Cleanup](#cleanup)

Throughout, hub commands run against the dev OpenBao API on
`127.0.0.1:8200`; spoke / proxy traffic runs on the gRPC port (default
`50053`). Adjust ports if your dev box is busy.

---

## Prerequisites

- Go toolchain version pinned in `.go-version` (build the `bao` binary with
  `make dev`).
- Docker for the PostgreSQL target (or any reachable Postgres ≥ 11).
- `openssl` (one CSR-validation test uses it).
- A scratch directory you can wipe between runs:
  ```bash
  export TESTDIR=/tmp/openbao-spoke-test
  mkdir -p "$TESTDIR"/spoke
  ```

Build once:

```bash
make dev
export PATH="$(go env GOPATH)/bin:$PATH"
bao version   # confirm 'OpenBao ... ' with the dev marker
```

---

## Automated unit tests

These run without any external dependencies and cover the cryptographic
primitives and protocol logic.

```bash
# Bootstrap primitives: token format, JWS-HS256, SPKI pin, CA + CSR signing.
go test -race -count=1 ./plugins/database/remote-db-plugin/bootstrap/...

# Runner cache discipline: slot/handler refcount, single-flighted cold-miss,
# Close-while-handler-in-flight, idle eviction, failed-Initialize cleanup,
# Shutdown closes every cached plugin. Uses a stubDB injected via the
# loadPluginFunc seam, so no real DB binary is required.
go test -race -count=1 ./plugins/database/remote-db-plugin/runner/...

# Proxy stream primitives: request_id register/deliver/cancel, failAll
# unblocks every waiter, touch/lastSeenAt freshness, concurrent
# register/deliver under the race detector.
go test -race -count=1 ./plugins/database/remote-db-plugin/...

# Registry / wiring sanity. Exercises the plugin catalog so all six
# remote-*-plugin names resolve.
go test -race -count=1 \
    ./helper/builtinplugins/... \
    ./vault/...                 \
    ./command/...
```

Optional: lint the plugin tree:

```bash
go tool -modfile=tools/go.mod golangci-lint run \
    ./plugins/database/remote-db-plugin/... \
    ./builtin/logical/relay/...             \
    ./command/...
```

---

## Bring up the test environment

A single shell with three panes makes this easiest: one for the hub, one
for the spoke daemon, one for operator commands.

### Pane 1 — dev hub

```bash
bao server -dev -dev-root-token-id=root \
    -dev-listen-address=127.0.0.1:8200 \
    2>&1 | tee "$TESTDIR/hub.log"
```

### Pane 3 — operator shell (set up env)

```bash
export BAO_ADDR=http://127.0.0.1:8200
export BAO_TOKEN=root
bao status   # confirm Unsealed=true, HA Mode=standalone
```

### Pane 2 — Postgres for the spoke to manage

```bash
docker run --rm -d --name openbao-test-pg \
    -e POSTGRES_PASSWORD=secret \
    -p 5432:5432 \
    postgres:16
```

Wait for it: `until docker exec openbao-test-pg pg_isready; do sleep 1; done`.

---

## Smoke: init → join → run → credentials

End-to-end happy path. Everything below runs in the operator shell unless
labelled otherwise.

### Hub initialization

```bash
bao relay init \
    -hub-endpoint=127.0.0.1:50053 \
    -hub-dns-sans=localhost \
    -hub-ip-sans=127.0.0.1 \
    -allowed-spoke-name=spoke-1 \
    -token-ttl=1h
```

Expect:

- A line beginning `Run the following on each spoke:` followed by a
  ready-to-paste `bao relay join …` command containing
  `-hub-cert-hash=sha256:…` and `-token=<id>.<secret>`.
- The hub log shows `[proxy] mTLS server listening on :50053`.

Copy the join command into a shell variable for convenience:

```bash
read -r -p "Paste the join cmd: " JOIN_CMD
```

### Spoke join

```bash
eval "$JOIN_CMD -address=$BAO_ADDR -credentials-dir=$TESTDIR/spoke"
ls -l "$TESTDIR/spoke"   # cert.pem, key.pem, ca.pem present
stat -c '%a %n' "$TESTDIR/spoke"/*.pem   # key.pem MUST be 0600
```

### Spoke daemon (pane 2 takes over from Postgres logs)

```bash
bao relay run \
    -server=127.0.0.1:50053 \
    -credentials-dir=$TESTDIR/spoke \
    2>&1 | tee "$TESTDIR/spoke.log"
```

Expect on stdout:

```
connecting to hub as spoke "spoke-1"
registered: Connected
```

Operator shell:

```bash
bao relay list
```

Expect: `Connected: 1 total, 1 healthy`, and a row
`spoke-1   0s ago … <CERT EXP>  OK`. The `CERT EXP` column shows the spoke's
client-cert expiry as a relative duration (e.g. `29d`). The machine-readable
form is `bao read relay/spokes`, where each spoke entry carries
`cert_not_after` (Unix seconds) equal to the spoke's current client-cert
`NotAfter`:

```bash
bao read -format=json relay/spokes | jq '.data.spokes[] | {name, cert_not_after}'
# cross-check against the on-disk cert:
date -d "@$(bao read -format=json relay/spokes | jq '.data.spokes[0].cert_not_after')" -u
openssl x509 -in $TESTDIR/spoke/cert.pem -noout -enddate
```

### Mount a remote-postgres-plugin

```bash
bao secrets enable database
bao write database/config/spoke-pg \
    plugin_name=remote-postgres-plugin \
    spoke_name=spoke-1 \
    connection_url='postgresql://{{username}}:{{password}}@127.0.0.1:5432/postgres?sslmode=disable' \
    username=postgres \
    password=secret \
    allowed_roles='readonly'

bao write database/roles/readonly \
    db_name=spoke-pg \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
    default_ttl=10m

bao read database/creds/readonly
```

Expect a `username` of the form `v-root-readonly-…` and a fresh password.
Verify the role landed in Postgres:

```bash
docker exec openbao-test-pg psql -U postgres -c '\du+' | grep readonly
```

---

## Token security

### Stderr secrecy warning

```bash
bao relay token create -ttl=1h 2>"$TESTDIR/warn" | tail -n +1
cat "$TESTDIR/warn"
```

Expect `$TESTDIR/warn` to begin with:
`This token is shown ONCE. Copy it now …`

### Generic sign-csr error (token enumeration defence)

Pick five token-failure cases and check the response is byte-identical:

```bash
# Generate a throwaway CSR so the request structure is valid.
go run ./scripts/dev/agent_make_csr.go -cn=spoke-1 -out=$TESTDIR/csr.pem || \
    openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) \
                -nodes -keyout /dev/null -subj /CN=spoke-1 \
                -out $TESTDIR/csr.pem

CSR="$(cat $TESTDIR/csr.pem)"

# (1) malformed token format
bao write relay/sign-csr token=garbage spoke_name=spoke-1 csr_pem="$CSR" 2>&1 | tail -1
# (2) syntactically valid id but never minted
bao write relay/sign-csr token=ababab.0000000000000000 spoke_name=spoke-1 csr_pem="$CSR" 2>&1 | tail -1
# (3) wrong secret on a real token (substitute one valid id, mangled secret)
bao write relay/sign-csr token=<real-id>.0000000000000000 spoke_name=spoke-1 csr_pem="$CSR" 2>&1 | tail -1
# (4) wrong spoke_name with a real allowed_spoke_name token
bao write relay/sign-csr token=<real-token> spoke_name=spoke-X csr_pem="$CSR" 2>&1 | tail -1
# (5) usage-restricted token (create one without signing usage)
bao write relay/bootstrap-tokens ttl=1h usages=authentication
bao write relay/sign-csr token=<that-token> spoke_name=spoke-1 csr_pem="$CSR" 2>&1 | tail -1
```

Every line must say exactly `token unknown or expired`. The real reason
appears in the hub log at WARN with the token id (`relay/sign-csr:
malformed token`, `relay/sign-csr: bad token secret`, etc.).

### Token revocation

```bash
bao relay token list
bao relay token revoke <id>
bao write relay/sign-csr token=<id>.<secret> spoke_name=spoke-1 csr_pem="$CSR" 2>&1 | tail -1
# → token unknown or expired
```

---

## CSR validation

The hub rejects CSRs that smuggle unexpected fields.

```bash
# (a) SANs — populate DNS names in the CSR.
cat > $TESTDIR/san.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions     = san
prompt             = no
[dn]
CN = spoke-1
[san]
subjectAltName = DNS:evil.example.com
EOF
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) \
            -nodes -keyout $TESTDIR/san.key -config $TESTDIR/san.cnf \
            -out $TESTDIR/san.pem
bao write relay/sign-csr token=<valid> spoke_name=spoke-1 \
    csr_pem="$(cat $TESTDIR/san.pem)"
# → "CSR must not include SANs"
```

```bash
# (b) sub-2048 RSA.
openssl req -new -newkey rsa:1024 -nodes \
            -keyout /dev/null -subj /CN=spoke-1 \
            -out $TESTDIR/rsa.pem
bao write relay/sign-csr token=<valid> spoke_name=spoke-1 \
    csr_pem="$(cat $TESTDIR/rsa.pem)"
# → "CSR RSA key is 1024 bits; require >= 2048"
```

```bash
# (c) Reserved CN.
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) \
            -nodes -keyout /dev/null -subj /CN=openbao-hub \
            -out $TESTDIR/hub.pem
bao write relay/sign-csr token=<valid> spoke_name=openbao-hub \
    csr_pem="$(cat $TESTDIR/hub.pem)"
# → "CN \"openbao-hub\" is reserved; …"
```

```bash
# (d) RenewCert — same checks. Easiest from a Go script that dials the
# proxy with the existing client cert and sends a bad CSR via
# AgentService.RenewCert. The CN-mismatch case is reachable from the CLI:
bao relay renew -server=127.0.0.1:50053 \
    -credentials-dir=$TESTDIR/spoke \
    -ttl=10m
# Tamper: hand-craft a CSR with CN=other and call RenewCert via grpcurl.
# Expect: "CSR CN \"other\" does not match authenticated spoke \"spoke-1\"".
```

---

## Renewal

### Auto-renewal threshold

Restart the spoke with a tight cadence so we can watch it tick:

```bash
# In the spoke pane, after stopping the previous run:
bao relay run \
    -server=127.0.0.1:50053 \
    -credentials-dir=$TESTDIR/spoke \
    -renew-check-every=10s \
    -renew-threshold=0.99
# The first tick should renew because the cert is past 99% of its lifetime
# only after ~30 days; for the test, request a short cert via -ttl in renew:
```

The cleaner exercise: issue a short cert via `bao relay renew -ttl=5m`,
restart `bao relay run` with `-renew-threshold=0.01`. The next tick (within
10s) renews. Look for:

- spoke log: `renewed cert for "spoke-1"; new expiry …`
- `bao relay ca status` (no change — that's the hub cert; renewal is the
  spoke cert).
- `openssl x509 -in $TESTDIR/spoke/cert.pem -noout -dates` shows a fresh
  `notAfter`.
- `bao read relay/spokes` reports the **updated** `cert_not_after` for the
  spoke, matching the new on-disk `notAfter`. Renewal happens in place over
  the live stream (no reconnect), so the hub re-records the expiry on
  `RenewCert` — the reported value moves forward without restarting the spoke.

### TTL cap (90d)

```bash
bao relay renew -server=127.0.0.1:50053 \
    -credentials-dir=$TESTDIR/spoke \
    -ttl=8760h            # one year
openssl x509 -in $TESTDIR/spoke/cert.pem -noout -dates
```

Expect `notAfter - notBefore ≈ 90 days`, not one year.

### CN mismatch refused

Generate a CSR with a different CN via openssl, then call `RenewCert` over
gRPC (see CSR validation §d). Hub returns
`CSR CN "<other>" does not match authenticated spoke "<peer>"`.

### Atomic on-disk swap

Run renew with `strace -f -e rename,fsync` or DTrace and confirm both
`fsync` calls (file + dir) fire between the two renames. A power-cut
between renames leaves disk in `(new cert, old key)` — the next
`tls.LoadX509KeyPair` fails loudly and a retry recovers.

---

## CA management

### `bao relay ca status -format=json`

```bash
bao relay ca status              # human-readable
bao relay ca status -format=json # machine-readable, valid JSON
```

Pipe the JSON through `jq`; confirm `ca_subject`, `hub_endpoint`,
`listener_port`, etc. land at top-level fields.

### Hub-only rotate (transparent)

```bash
bao relay ca status > "$TESTDIR/before.txt"
bao relay ca rotate
bao relay ca status > "$TESTDIR/after.txt"
diff "$TESTDIR/before.txt" "$TESTDIR/after.txt" | head -20
```

Expect `ca_cert_hash` UNCHANGED (same root). `hub_cert_not_after` and
`hub_cert_subject` may move. The connected spoke remains healthy in
`bao relay list` — the spoke keeps its old client cert, the hub keeps
serving from the same CA root.

### Full rotate (`-full -yes`)

Destructive: invalidates every spoke cert. Reserve for the cleanup phase
or run in a separate test directory. Confirms the warning text appears.

### `relay/ca/update-endpoint`

```bash
# Comma-separated form. hub_dns_sans / hub_ip_sans are TypeCommaStringSlice
# so a single value is split into multiple SANs; repeated key=value pairs
# also work for operators who prefer that shape.
bao write relay/ca/update-endpoint \
    hub_endpoint=127.0.0.1:50053 \
    hub_dns_sans=localhost,hub.example.com
bao relay ca status -format=json | jq -r '.hub_dns_sans[]'

# Sanity-check the cert the listener actually presents.
echo | openssl s_client -connect 127.0.0.1:50053 -servername localhost 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName
```

Expect two separate DNS SANs (`localhost`, `hub.example.com`) in both the
status output and the live cert — not a single SAN `"localhost,hub.example.com"`.
The running spoke is unaffected (it has its own pinned `-server`).

### CA mutation serialization

In two operator shells, fire `bao relay ca init -hub-endpoint=… -force` at
the same time:

```bash
( bao relay ca status >/dev/null ; \
  for i in 1 2 3; do bao relay ca rotate & done ; wait )
bao relay ca status -format=json | jq -r '.ca_cert_hash'
```

Each request returns one of: success, or the explicit "CA already
initialized" / lock-blocked behaviour. The on-disk CA after the dust
settles is internally consistent — same hash returned from `ca/info`,
same hash echoed in `bao relay list`.

---

## Failure modes

### Spoke restart self-heals

```bash
# In the spoke pane: Ctrl+C the daemon, then restart.
bao relay run -server=127.0.0.1:50053 -credentials-dir=$TESTDIR/spoke
```

Hub logs `spoke "spoke-1" reconnected; tearing down old stream`. Issue a
fresh credential request:

```bash
bao read database/creds/readonly
```

Expect success on the first try (cache-miss → re-Initialize from the
config the hub embeds in NewUser).

### Graceful shutdown (SIGINT/SIGTERM)

```bash
# Spoke pane:
^C
# Expect:
# shutdown signal received; draining
# hub disconnected
# exit code 0
echo $?
```

In the hub log expect `spoke "spoke-1" disconnected` shortly after. With
strace you can confirm no orphaned `pq` / mysql connections survive past
the daemon exit:

```bash
ss -tnp | grep openbao || true   # nothing referencing the old PID
```

### Hub restart

```bash
# Hub pane: Ctrl+C, restart with same dev token.
bao server -dev -dev-root-token-id=root -dev-listen-address=127.0.0.1:8200
```

`-dev` wipes state, so for a real check use `-dev-no-store-token` plus
file-backed dev mode, or run an HA cluster. With persistent storage:

- Hub starts, relay backend hydrates `ca/bundle` from storage.
- Proxy listener restarts on the same port.
- The spoke (still alive in pane 2) reconnects within ~40s
  (gRPC keepalive trips on the old TCP, dial loop retries).
- `bao relay list` shows the spoke healthy again.

### Two daemons, same credentials dir

```bash
# Pane 2 spoke is running. Start a second from a different shell:
bao relay run -server=127.0.0.1:50053 -credentials-dir=$TESTDIR/spoke
```

Expect both daemons to "ping-pong": each new connection kicks the other
off. `bao relay list` shows the spoke flapping. The fix surfaces during
*join*, not run — `bao relay join` refuses an already-populated dir:

```bash
bao relay join … -credentials-dir=$TESTDIR/spoke
# → "$TESTDIR/spoke already contains spoke credentials. Pass -force …"
```

### Half-rotated credentials (chain verify at startup)

Simulate a credentials directory whose `cert.pem` and `ca.pem` belong to
different CAs (e.g. partial re-join, partial restore from backup). The
spoke must refuse to start, not fail opaquely at first gRPC handshake.

```bash
# Snapshot the good credentials first.
cp -a "$TESTDIR/spoke" "$TESTDIR/spoke.bad"

# Replace ca.pem with one from an unrelated CA.
openssl ecparam -name prime256v1 -genkey -noout -out "$TESTDIR/bad-ca.key"
openssl req -x509 -new -key "$TESTDIR/bad-ca.key" -days 1 \
    -subj '/CN=unrelated-ca' -out "$TESTDIR/spoke.bad/ca.pem"

# bao relay run must reject this directory at startup.
bao relay run -server=127.0.0.1:50053 -credentials-dir="$TESTDIR/spoke.bad"
# → "tls: spoke cert in $TESTDIR/spoke.bad failed verification: x509: certificate signed by unknown authority"
# Exit code != 0.

# bao relay renew must do the same — both paths share loadSpokeTLS.
bao relay renew -server=127.0.0.1:50053 -credentials-dir="$TESTDIR/spoke.bad"
# → same error.

rm -rf "$TESTDIR/spoke.bad"
```

### Bricked endpoint (hydration must not block admin)

Corrupt the persisted endpoint via raw API:

```bash
bao write relay/ca/update-endpoint hub_endpoint=':not-a-port'
# Should be rejected at the field level. If you bypass via direct storage
# write, restarting the hub now logs:
#   relay: stored hub_endpoint cannot be parsed; proxy listener not
#   started — admin paths remain reachable…
# The admin paths must still work; verify:
bao read relay/ca/info
bao write relay/ca/update-endpoint hub_endpoint=127.0.0.1:50053
```

The mount stays usable in degraded mode; operators fix it in-band.

---

## Namespaced lease revocation

Confirm a lease created in an OpenBao **namespace** revokes correctly over the proxy —
the case the KubeVault hub-spoke tenant-isolation design flagged (per-tenant mounts at
`<org-id>/k8s.<spoke>.…`). The proxy carries **no** `X-Vault-Namespace`; correctness comes
from the per-config `plugin_instance_id` (namespace-unique) plus OpenBao resolving the
namespace above the plugin layer. See DESIGN.md → *Namespaces and lease revocation*.

```bash
# A namespace to stand in for a tenant org.
bao namespace create org-acme

# Mount the SAME remote plugin inside the namespace. Its config mints its OWN
# plugin_instance_id, distinct from the root mount configured earlier.
bao secrets enable -namespace=org-acme database
bao write -namespace=org-acme database/config/spoke-pg \
    plugin_name=remote-postgres-plugin \
    spoke_name=spoke-1 \
    connection_url='postgresql://{{username}}:{{password}}@127.0.0.1:5432/postgres?sslmode=disable' \
    username=postgres \
    password=secret \
    allowed_roles='readonly'
bao write -namespace=org-acme database/roles/readonly \
    db_name=spoke-pg \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
    default_ttl=10m

# The two mounts must hold DIFFERENT instance ids (no cross-namespace collision).
bao read -namespace=org-acme -field=plugin_instance_id database/config/spoke-pg
bao read                     -field=plugin_instance_id database/config/spoke-pg
# → two distinct 24-hex values.

# Issue a credential in the namespace and confirm the role landed in Postgres.
CRED=$(bao read -namespace=org-acme -format=json database/creds/readonly)
LEASE=$(echo "$CRED" | jq -r .lease_id)
DBUSER=$(echo "$CRED" | jq -r .data.username)
docker exec openbao-test-pg psql -U postgres -c '\du' | grep "$DBUSER"   # present

# Force-revoke by prefix INSIDE the namespace — the path the operator uses for
# SecretAccessRequest teardown (sys/leases/revoke-force/<prefix> + X-Vault-Namespace).
bao lease revoke -namespace=org-acme -force -prefix database/creds/readonly
# equivalently: bao write -namespace=org-acme -f sys/leases/revoke-force/database/creds/readonly

# The spoke dropped the DB user (spoke log shows DeleteUser for the namespaced
# mount's instance_id); the lease is gone from the namespace.
docker exec openbao-test-pg psql -U postgres -c '\du' | grep "$DBUSER" || echo "revoked: user dropped"
bao list -namespace=org-acme sys/leases/lookup/database/creds/readonly 2>&1 | grep -q "$LEASE" && echo "LEASE STILL PRESENT (fail)" || echo "lease cleared"
```

Cache-miss variant (force-revoke after a spoke restart still reaches the DB):

```bash
# Issue a fresh cred, then restart the spoke so the hub holds an instance_id the
# spoke no longer has cached.
CRED=$(bao read -namespace=org-acme -format=json database/creds/readonly)
DBUSER=$(echo "$CRED" | jq -r .data.username)
# In the spoke pane: Ctrl+C `bao relay run`, then start it again.
bao lease revoke -namespace=org-acme -force -prefix database/creds/readonly
# Spoke log: "cache miss … re-Initialize from request config" then DeleteUser.
docker exec openbao-test-pg psql -U postgres -c '\du' | grep "$DBUSER" || echo "revoked after restart: user dropped"
```

Expected: distinct instance ids per namespace; the namespaced force-revoke drops the
Postgres user and clears the lease; the restart variant self-heals and still drops the
user. No `X-Vault-Namespace` appears on the gRPC wire (the proxy only ever sends
`instance_id`).

---

## Concurrency

Confirm many in-flight `db/creds/readonly` reads do not serialize on a
single spoke.

```bash
# Without parallel: ~1 RTT per request, sequential.
time for i in $(seq 1 20); do bao read database/creds/readonly >/dev/null; done

# With parallel: should be roughly the slowest single call, NOT 20×.
time seq 1 20 | xargs -P 20 -I{} bao read database/creds/readonly >/dev/null
```

Expect the parallel run to finish in ~1–2× the slowest single response
time (depending on Postgres concurrency limits), not 20× the average. In
the hub log, every request gets a distinct `request_id`; in the spoke log,
`runner` reports them all dispatched concurrently on the worker pool.

Capture the timing for the PR:

```bash
time seq 1 50 | xargs -P 50 -I{} bao read database/creds/readonly >/dev/null
```

---

## Cleanup

```bash
bao namespace delete org-acme 2>/dev/null || true
docker rm -f openbao-test-pg
# Stop the hub and spoke panes (Ctrl+C each).
rm -rf "$TESTDIR"
```

---

## Test matrix summary

A condensed view for the PR description's checklist:

| Area | Command / scenario | Expected |
| --- | --- | --- |
| Unit — bootstrap | `go test -race ./.../bootstrap/...` | green |
| Unit — runner | `go test -race ./.../runner/...` | green (stubDB-backed cache discipline tests) |
| Unit — proxy primitives | `go test -race ./plugins/database/remote-db-plugin/...` | green |
| Unit — wiring | `go test -race ./helper/builtinplugins/... ./vault/... ./command/...` | green |
| Smoke E2E | init → join → run → list → enable database → creds | spoke healthy; cred returned |
| Token secrecy | `bao relay token create` | stderr warning before token |
| Token enumeration | five sign-csr failure variants | identical `"token unknown or expired"` |
| CSR — SAN | openssl with `subjectAltName` | `"CSR must not include SANs"` |
| CSR — small RSA | openssl rsa:1024 | `"require >= 2048"` |
| CSR — reserved CN | CN=openbao-hub | `"is reserved"` |
| CSR — CN mismatch on RenewCert | hand-crafted CSR via grpcurl | `"does not match authenticated spoke"` |
| Renewal — auto | short cert + low threshold | new `notAfter` within a tick |
| Renewal — TTL cap | `-ttl=8760h` | issued cert ≤ 90d |
| Spoke cert expiry | `bao read relay/spokes` while connected | `cert_not_after` == client-cert `NotAfter`; updates after `RenewCert` (no reconnect) |
| CA — `-format=json` | `bao relay ca status -format=json` | valid JSON |
| CA — hub rotate | `bao relay ca rotate` | `ca_cert_hash` unchanged, spoke stays healthy |
| CA — update-endpoint (CSV) | `bao write relay/ca/update-endpoint hub_dns_sans=a,b` | two distinct SANs in `ca/info` *and* in the live listener cert |
| Failure — spoke restart | kill `bao relay run`, restart | cache-miss self-heal, next creds OK |
| Namespaced revocation | mount in `org-acme`, issue cred, `bao lease revoke -namespace=org-acme -force -prefix …` | distinct `instance_id` per namespace; DB user dropped; lease cleared; no `X-Vault-Namespace` on the wire |
| Failure — SIGTERM | Ctrl+C the spoke | exit 0, no leaked sockets |
| Failure — duplicate dir | join into populated dir without `-force` | refused |
| Failure — half-rotated creds | swap ca.pem for an unrelated CA, restart spoke | `bao relay run` refuses at startup with "failed verification: x509: certificate signed by unknown authority" |
| Concurrency | 20× parallel `db/creds/readonly` | roughly slowest single, not 20× |
