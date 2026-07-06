# AGENTS.md

This file provides guidance to coding agents (Claude Code, etc.) when working with code in this repository.

## Repository

OpenBao is a community fork of HashiCorp Vault (secrets management). This working copy is a personal fork carrying additional work — most notably the **remote-db-plugin** under `plugins/database/remote-db-plugin/`, a hub-and-spoke architecture that lets one OpenBao instance proxy database credential management to spoke clusters over gRPC.

## Common commands

The Go toolchain version is pinned in `.go-version`. `CGO_ENABLED` defaults to 0 unless a target overrides it.

### Build
- `make dev` — build local dev binary into `./bin/bao` and `$GOPATH/bin` (sets `OPENBAO_DEV_BUILD=1`).
- `make bin` — build the equivalent of releasable binaries (`BUILD_TAGS='ui'`).
- `go build -o bin/bao .` — quickest path to a `bao` binary without scripts.
- `make dev-ui` — dev build that includes the compiled Ember UI (requires `make ember-dist` first or `assetcheck` will fail).
- `make <db>-database-plugin` — build a standalone database plugin binary, e.g. `make postgresql-database-plugin`.

### Run a dev server
- `go run . server -dev` (or `./bin/bao server -dev`).

### Test
- `make test` — unit tests for the root module **plus** `api/v2/...` and `sdk/v2/...`, with `BAO_*` env vars cleared and a 45-minute timeout. The list of packages is in the `TEST` variable.
- `make testrace` — same with `-race` and `CGO_ENABLED=1` (extended timeout).
- `make testacc TEST=./some/package` — acceptance tests (sets `BAO_ACC=1`; refuses to run against `./...`).
- Single package: `go test ./some/package`. Single test: `go test ./some/package -run TestName`.

### Lint / vet / format
- `make vet` — `go vet` across every Go module in the tree.
- `make lint` — `golangci-lint` (runs via `go tool -modfile=tools/go.mod`). `make lint-new` lints only the current commit. `make deprecations` runs the staticcheck config in `.golangci.deprecations.yml`.
- `make fmt` — `gofumpt -w .`. `make fmtcheck` is the read-only check used by the pre-commit hook.
- `make bootstrap` — install the dev tools declared in `tools/go.mod` (golangci-lint, gofumpt, govulncheck, misspell, etc.).

### Protobuf
- `make proto` — regenerate all `*.pb.go` from `.proto` files. Requires `protoc` matching `PROTOC_VERSION` in the Makefile (currently 34.0). The recipe also runs a set of `sed` post-processing rules; **do not add new ones** (comment in the Makefile says so explicitly) — use the protobuf-native names instead.

### Modules
This repo is a multi-module workspace: `./go.mod` (root), `api/go.mod`, `sdk/go.mod`, `tools/go.mod`. `make tidy-all` runs `go mod tidy` in each. CI enforces this via `make ci-tidy-all`.

### UI
The Ember UI lives in `ui/`. `make install-ui-dependencies` runs `pnpm install`; `make test-ember` runs the Ember test suite; `make ember-dist` produces the assets the Go binary embeds via `make dev-ui`.

## Commit / sign-off

All commits must carry a `Signed-off-by` trailer per the project's DCO policy — always use `git commit -s`. Do not amend signed-off commits without re-signing.

## High-level architecture

OpenBao is structured as a server core + a plugin ecosystem + an HTTP/gRPC surface.

- **`vault/`** — the server core. `core.go` is the `Core` struct that holds the seal/unseal state, mount table, request router, expiration manager, identity store, etc. Subpackages here implement audit, auth, cluster management, raft forwarding (`forwarding/`), identity (`identity/`), policies, sealing, and so on. This is the package you change when modifying *how* OpenBao itself runs, not what backends it exposes.
- **`http/`** — the HTTP front door. Wraps `vault.Core` with handlers, forwarding, CORS, and the proxy logic that forwards to active raft nodes. Also embeds the compiled UI when built with `-tags ui`.
- **`command/`** — the `bao` CLI. Every subcommand has a file pair (`mount.go` / `mount_test.go` style). Also hosts the `agent` and `proxy` long-running modes.
- **`api/`** (module `github.com/openbao/openbao/api/v2`) — the Go client SDK that external programs import. Separate `go.mod`.
- **`sdk/`** (module `github.com/openbao/openbao/sdk/v2`) — the *plugin* SDK. `sdk/framework/` is the `Backend` / `Path` machinery every secrets and auth plugin uses; `sdk/logical/` defines `Request`/`Response` and the gRPC contract; `sdk/database/dbplugin/v5/` is the current database plugin protocol. Also a separate module.
- **`builtin/`** — first-party plugins compiled into `bao`. `builtin/credential/<name>` are auth methods (approle, jwt, kubernetes, ldap, userpass, …). `builtin/logical/<name>` are secrets engines (kv, pki, transit, ssh, database, …). `builtin/audit/` are audit sinks. `builtin/plugin/` is the loader for external plugins.
- **`helper/builtinplugins/registry.go`** — central registry that wires each builtin into the running server by name. **New builtin plugins must be registered here.**
- **`plugins/database/<engine>/`** — standalone database plugin binaries (postgres, mysql, cassandra, influxdb, valkey, plus this fork's `remote-db-plugin`). They use `sdk/database/dbplugin/v5` over gRPC.
- **`physical/`** — storage backends used by the seal/unseal core. `physical/raft/` is the embedded raft storage; `physical/postgresql/` is the SQL-backed alternative.
- **`audit/`** — top-level audit broker that fans out to `builtin/audit/*` sinks.
- **`serviceregistration/`** — pluggable registration backends (consul, k8s, kubernetes) used by HA setups.

### Plugin model in one paragraph

OpenBao plugins are out-of-process gRPC servers managed by `go-plugin`. A *secrets engine* or *auth method* implements `logical.Backend` (via `sdk/framework.Backend`); a *database plugin* implements the v5 `dbplugin.Database` interface (Initialize/NewUser/UpdateUser/DeleteUser). Builtin plugins are registered in `helper/builtinplugins/registry.go` and loaded in-process; external plugins are launched via the plugin catalog and communicate over gRPC defined in `sdk/database/dbplugin/v5/proto/`.

### The remote-db-plugin (this fork)

`plugins/database/remote-db-plugin/` adds a hub-and-spoke variant of database plugins. See `plugins/database/remote-db-plugin/DESIGN.md` for the full architecture; the short version:

- **`proxy.go`** runs inside the hub OpenBao process and presents itself as a normal v5 database plugin (`remote-postgres-plugin`, `remote-mysql-plugin`, etc.). It forwards every `Initialize` / `NewUser` / `UpdateUser` / `DeleteUser` / `Close` call to the spoke identified by `spoke_name` over a long-lived mTLS gRPC stream. Each request carries a stable `instance_id` so the spoke can cache the underlying plugin instance instead of re-Initializing on every call. The proxy gRPC listener is started by `bao relay init` (not lazily on first DB mount). Backed by `proxy_test.go` covering the in-flight register/deliver/cancel discipline, `failAll` teardown, freshness accounting, and `newRequestID` uniqueness.
- **`bootstrap/`** — kubeadm-style trust primitives: token format `<id>.<secret>`, detached JWS-HS256 over the cluster-info bundle, SPKI-hash pin for the spoke-CA, plus the CA generation and CSR signing used by `bao relay init` / `bao relay join` / `bao relay renew`. Exports `DecodeCSRPEM` as the shared strict PEM-envelope decoder; both `relay/sign-csr` and `proxy.RenewCert` route through it so trailing-data / block-type substitution is rejected the same way on both entry points. Backed by focused unit tests.
- **`runner/`** — spoke-side dispatcher. Holds the per-`instance_id` plugin cache (single-flighted on cold-miss, refcounted while in use, idle-evicted after 24h) and dispatches incoming JSON requests to the in-process built-in database plugins. The plugin factory is reached through a package-level `loadPluginFunc` seam so `runner_test.go` can stub it with an in-memory `dbplugin.Database` and exercise the cache discipline (refcount, single-flight, idle eviction, Close-while-in-flight, Shutdown) without a real DB.
- **`proto/agent.proto`** — the gRPC contract: a bidi `Connect` stream for ongoing requests + heartbeats + responses (correlated by `request_id`), and a unary `RenewCert` for spoke-cert renewal authenticated by the existing mTLS client cert.
- **`builtin/logical/relay/`** — the `relay/` logical backend the hub mounts. Manages the spoke-CA, hub TLS identity, and seal-wrapped bootstrap tokens; serves the unauthenticated `cluster-info` and `sign-csr` paths used by `bao relay join`. `handleSignCSR` evaluates every per-token check (secret HMAC, expiry, usage, allowed_spoke_name) against a placeholder when the id is unknown, so "unknown id" pays the same per-field cost as "wrong secret" and an attacker holding any valid token cannot time-distinguish live ids from dead ones.
- **`command/relay_*.go`** — the operator CLI: `bao relay init | join | run | list | renew | ca status | ca rotate | token create | list | revoke`. `bao relay run` is the long-running spoke daemon and ships inside the same `bao` binary; `loadSpokeTLS` verifies the local cert chains to the bundled `ca.pem` at startup (mirrors the hub-side check in `bootstrap.SetIdentity`) and pins TLS 1.3 client-side to match the hub's floor. The relay backend also exposes `relay/ca/update-endpoint` for non-destructive endpoint/SAN refresh — invoked via raw `bao write`, not a dedicated subcommand. `hub_dns_sans` / `hub_ip_sans` are `TypeCommaStringSlice`, so `hub_dns_sans=a,b` splits into two SANs the way operators expect.
- **`yaml/`** — Kubernetes manifests for hub OpenBao + spoke agent deployments (KubeVault-based). May lag behind the rest of the tree; treat as starting points.

The two top-level scripts `build-cli-image.sh` and `build-hub-spoke.sh` are personal build helpers — they hard-code `/home/rudro25/...` paths and are not portable; treat them as references rather than entry points when working in this checkout.
