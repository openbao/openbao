## 2.6.0-beta20260622
## June 22, 2026

FEATURES:

* **Namespace Sealing**: Allow Shamir seal configuration on namespace creation. [[GH-3297](https://github.com/openbao/openbao/pull/3297)]
  - Partitions tenant storage with distinct cryptographic key material.
  - Allows tenants to revoke access to their namespace via seal operation without impacting other tenants.
  - Uses global synchronization of namespace seal status, allowing easier management from multi-node deployments.
* **Auto Unseal plugins**: Add a new `kms` plugin type that enables Auto Unseal mechanisms to be distributed as external binary plugins. [[GH-2586](https://github.com/openbao/openbao/pull/2586)]
  - Declaratively register KMS plugins via `plugin "kms" "name" { }` stanzas in the server configuration, making `"name"` available as an Auto Unseal mechanism via `seal "name" { }`.
  - KMS plugins automatically restart and recover from crashes, avoiding a full instance restart when a seal reaches a bad state (e.g., via a misbehaving PKCS#11 library).
  - Pre-built plugins for many of the seals currently built into OpenBao are available at https://github.com/openbao/openbao-plugins. A plugin-based seal takes priority over a built-in seal if a matching plugin is installed. Note that several provider-specific built-in seals will be removed from OpenBao in v2.7.0 and remain available as external plugins only. Also see the deprecations section of these release notes.
  - Develop custom Auto Unseal mechanisms tailored to your use case using the [SDK](https://github.com/openbao/go-kms-wrapping/tree/main/plugin).
* **Workflows**: This adds new endpoints under `sys/workflows` to allow operators to create workflows and users to execute them.
  - Workflows allow the creation of simplified or managed interfaces over OpenBao's standard API.
  - Use of the `allow_unauthenticated_workflows` server configuration value enables unauthenticated execution of workflows; any dispatched requests still require authentication but this can be provided as a request parameter.
  - Workflows are built on the common profile engine powering declarative self-initialization and use the same syntax. [[GH-2728](https://github.com/openbao/openbao/pull/2728)]
* **Authenticated root generation**: New `/sys/generate-root-token` endpoints are available as replacements for the deprecated unauthenticated ones. [[GH-3041](https://github.com/openbao/openbao/pull/3041)]
* **Distroless container images**: This is a new container image variant based on [distroless/static](https://github.com/GoogleContainerTools/distroless), available as `openbao-distroless`. The only executable contained in these images is OpenBao itself. [[GH-2592](https://github.com/openbao/openbao/pull/2592)]

IMPROVEMENTS:

* command: Allow overriding the location of `~/.vault-token` via the `BAO_TOKEN_PATH` environment variable. [[GH-2706](https://github.com/openbao/openbao/pull/2706)]
* command/server: Error when unknown keys are present in the declarative self-initialization configuration. [[GH-2883](https://github.com/openbao/openbao/pull/2883)]
* command/server: Add CEL support to self-initialization, allowing finer control over structuring requests. [[GH-2671](https://github.com/openbao/openbao/pull/2671)]
* command/server: Add `text/template` support to self-initialization, allowing templating of values from other requests/responses. [[GH-2727](https://github.com/openbao/openbao/pull/2727)]
* command/server: Allow conditional execution of self-initialization requests with `when` keyword. [[GH-2739](https://github.com/openbao/openbao/pull/2739)]
* command/server: Allow self-initialization stanzas in development server mode. [[GH-2463](https://github.com/openbao/openbao/pull/2463)]
* command/server: Allow setting headers on declarative self-initialization requests. [[GH-2737](https://github.com/openbao/openbao/pull/2737)]
* command/agent: Add `uid` and `gid` configuration options for the `file` sink. [[GH-2851](https://github.com/openbao/openbao/pull/2851)]
* command/agent: `SIGHUP` now reloads the client TLS configuration. [[GH-3038](https://github.com/openbao/openbao/pull/3038)]
* command/login: Support Kubernetes service account token authentication via `-method=kubernetes` with both interactive and non-interactive modes. [[GH-1891](https://github.com/openbao/openbao/pull/1891)]
* http: Always include full JSON parse and complexity errors in the response instead of hiding it behind a constant error message. [[GH-3240](https://github.com/openbao/openbao/pull/3240)]
* http: Ensure that `passthrough_request_headers` can pass the `Host` header to plugins. [[GH-3325](https://github.com/openbao/openbao/pull/3325)]
* core: The `sys/` backend is now a singleton shared across all namespaces, reducing idle memory usage of the OpenBao instance. [[GH-3007](https://github.com/openbao/openbao/pull/3007)]
* core/leases: Lease lookup responses will now include `path`, `namespace_path` and `revoke_error`. [[GH-1906](https://github.com/openbao/openbao/pull/1906)]
* core/listeners: Add a parameter to allow cross-origin requests to include credentials (`Access-Control-Allow-Credentials` header). [[GH-2262](https://github.com/openbao/openbao/pull/2262)]
* seal/azurekeyvault: Support explicitly setting Azure authentication methods and add support for authenticating using Azure managed identities. [[GH-2519](https://github.com/openbao/openbao/pull/2519)]
* seal/pkcs11: When using public/private key encryption, fall back to finding the public key via the private key's `CKA_ID` if both key halves did not share the same `CKA_LABEL`. [[GH-3231](https://github.com/openbao/openbao/pull/3231)]
* physical/raft: Detect, log, and rollback transactions that have never been committed or rolled-back. If you see the message "transaction was leaked" in your logs, please open an issue. [[GH-2185](https://github.com/openbao/openbao/pull/2185)]
* physical/raft: Improve snapshot duration while slightly increasing snapshot size. [[GH-3061](https://github.com/openbao/openbao/pull/3061)]
* auth/cert: Add support for `X-Tls-Client-Cert`, to allow processing of a leaf certificate forwarded from a TLS-terminating reverse proxy. [[GH-2080](https://github.com/openbao/openbao/pull/2080)]
* auth/jwt: Add new Kubernetes JWT provider that authenticates to the Kubernetes API using a pod's service account token. [[GH-2114](https://github.com/openbao/openbao/pull/2114)]
* auth/kerberos: Add the `decode_pac` option in order to improve compatibility with Kerberos systems. [[GH-2211](https://github.com/openbao/openbao/pull/2211)]
* auth/userpass: Add `password_hash` field to allow providing a pre-hashed bcrypt password instead of plaintext. [[GH-2702](https://github.com/openbao/openbao/pull/2702)]
* secrets/pki: Add encode_json and decode_json CEL helpers. [[GH-1549](https://github.com/openbao/openbao/pull/1549)]
* secrets/totp: Add `generated`, `expire_time`, and `period` fields to code generation response. [[GH-2585](https://github.com/openbao/openbao/pull/2585)]
* secrets/ssh: Search for public and private key files if `-public-key-path` and `-private-key-path` flags aren't given, respectively. [[GH-2419](https://github.com/openbao/openbao/pull/2419)]
* database/mysql: Add multi-host connection failover support. Connection URLs can now specify multiple hosts (e.g., `tcp(host1:3306,host2:3306)`) for automatic failover when a host becomes unavailable. [[GH-2312](https://github.com/openbao/openbao/pull/2312)]
* api, sdk: Add additional constants for commonly used headers. [[GH-2323](https://github.com/openbao/openbao/pull/2323)]
* api: Add `ClientCertBytes` and `ClientKeyBytes` as possible in-memory cert contents in `TLSConfig`. [[GH-2798](https://github.com/openbao/openbao/pull/2798)]
* api: Add first-class support for `/sys/namespaces` APIs via `.Sys().CreateNamespace(...)` & co. [[GH-2955](https://github.com/openbao/openbao/pull/2955)]
* api: Add methods to list and scan keys to the KVv1 and KVv2 client. [[GH-3220](https://github.com/openbao/openbao/pull/3220)]
* api: Allow disabling automatic configuration from environment variables in the API client via a `DisableEnvironment` field on `Config` and a `NewConfig` constructor to create clean client configurations. [[GH-2834](https://github.com/openbao/openbao/pull/2834)]
* sdk/helper/consts: Add `AllowedJWTSignatureAlgorithmsEAB`. [[GH-2464](https://github.com/openbao/openbao/pull/2464)]
* ui: Add `lang="en"` attribute to `html` tag. [[GH-2580](https://github.com/openbao/openbao/pull/2580)]
* ui: Update EmberJS to v4.12 LTS. [[GH-2653](https://github.com/openbao/openbao/pull/2653)]

CHANGES:

* command: Remove buffering and delayed release of logs during startup phase of `server`, `agent`, `proxy` & `debug` subcommands. This includes the removal of the undocumented and hidden `-disable-gated-logs` flag. [[GH-2620](https://github.com/openbao/openbao/pull/2620)]
* command: `operator generate-root` now uses the authenticated `/sys/generate-root-token` endpoints instead of the deprecated `/sys/generate-root` endpoints. [[GH-3190](https://github.com/openbao/openbao/pull/3190)]
* core: `net/http.ServeMux` in Go 1.26 now uses a 307 redirect instead of a 301 redirect when given a bare path which doesn't exist in the multiplexer but which a path with a trailing slash exists for. This causes some `POST`/`PUT` operations to fail with a 400 instead of 404, as OpenBao does not allow writes to paths ending in a slash. See also: https://go.dev/doc/go1.26. [[GH-3072](https://github.com/openbao/openbao/pull/3072)]
* core/identity: Remove corrupt namespace identity groups created prior to v2.5.0 during unseal; affected groups must be recreated by an administrator. Check for `deleting corrupt group` in server startup logs. [[GH-2454](https://github.com/openbao/openbao/pull/2454)]
* sys/init, sys/rekey/init: The `stored_shares` parameter was removed and will now be ignored. [[GH-2662](https://github.com/openbao/openbao/pull/2662)]
* sys/seal-status: Renamed misleading `build_date` response field to `commit_date`. [[GH-2678](https://github.com/openbao/openbao/pull/2678)]
* sys/version-history: Renamed misleading `build_date` response field to `commit_date`. [[GH-2678](https://github.com/openbao/openbao/pull/2678)]
* api: Removed the `StoredShares` field from `InitRequest` and `RotateInitRequest` structs. [[GH-2662](https://github.com/openbao/openbao/pull/2662)]
* api: `(*Sys).GenerateRoot*` methods now use the authenticated `/sys/generate-root-token` endpoints instead of the deprecated `/sys/generate-root` endpoints. [[GH-3190](https://github.com/openbao/openbao/pull/3190)]
* packaging: Renamed misleading ldflags definition `BuildDate` to `CommitDate`. Build systems need to adjust their pipelines to reflect this change. [[GH-2678](https://github.com/openbao/openbao/pull/2678)]
* packaging/container: Removed `name`, `maintainer`, `vendor`, `version`, `release`, `revision`, `summary`, and `description` labels from container images in favor of the already attached [OpenContainers labels](https://github.com/opencontainers/image-spec/blob/main/annotations.md). If you have tooling that relies on these labels, instruct it to use the OpenContainers labels instead. [[GH-2589](https://github.com/openbao/openbao/pull/2589)]
* packaging/container: The openbao & openbao-hsm container images now run under the `openbao` user rather than the `root` user by default, matching the default behavior of openbao-ubi variants:
  - Note that the container entrypoint will always drop down to the `openbao` user before starting OpenBao even if started as `root`. The additional capabilities are only used pre-startup to automatically fix up permissions of files accessed by OpenBao. [[GH-2589](https://github.com/openbao/openbao/pull/2589)]
  - If you rely on the container initially running as `root` by default, you can revert to this behavior by manually specifying the user in your container engine.
* packaging/ui: Switch from `yarn` to `pnpm`. [[GH-2791](https://github.com/openbao/openbao/pull/2791)]
* releases: Artifacts on GitHub now follow consistent naming across archives, SBOMs and signatures. Most notably, "x86_64" or "amd64" is now always "amd64", and the operating system is always lowercased. [[GH-3209](https://github.com/openbao/openbao/pull/3209)]
* releases: Checksums are now provided as a single, consolidated `checksums.txt` artifact as opposed to per-OS checksum files such as `checksums-linux.txt`. [[GH-3209](https://github.com/openbao/openbao/pull/3209)]

BUG FIXES:

* command: Fix `bao operator rotate-keys` and `bao operator rekey` warning about new key shares when rotating the barrier root key only. [[GH-2648](https://github.com/openbao/openbao/pull/2648)]
* core/seal: Fix `/sys/rotate/root/update` returning a random, unused key share value when rotating the barrier root key using recovery keys. [[GH-2648](https://github.com/openbao/openbao/pull/2648)]
* core/listeners: Close HTTP servers first before closing the underlying listener. [[GH-2703](https://github.com/openbao/openbao/pull/2703)]
* core/namespaces: Fix PATCH on a namespace returning status 500 on missing or nonexistent namespace. [[GH-2955](https://github.com/openbao/openbao/pull/2955)]
* core/auth: Ensure inline auth does not generate in-memory lease information. [[GH-3343](https://github.com/openbao/openbao/pull/3343)]
* core/mfa: Handle invalidation for login MFA within namespaces, ensuring standby nodes respond appropriately on writes. [[GH-3283](https://github.com/openbao/openbao/pull/3283)]
* seal/pkcs11: Fix "invalid key format" error when `key_id` is provided but `key_label` is not. [[GH-3231](https://github.com/openbao/openbao/pull/3231)]
* seal/pkcs11: Properly strip hex prefix when setting `key_id` as hex value. [[GH-3231](https://github.com/openbao/openbao/pull/3231)]
* physical/raft: Forward bootstrap challenge/answer requests to active node, fixing raft join failures via load balancer. [[GH-2976](https://github.com/openbao/openbao/pull/2976)]
* sys/plugin: Fix plugin reload returning success for non-existent plugin. [[GH-2398](https://github.com/openbao/openbao/pull/2398)]
* sys/quotas: Fix unintentional attempts to delete quotas on standby nodes when mount is removed. [[GH-3316](https://github.com/openbao/openbao/pull/3316)]
* secrets/pki: Add missing migration for `not_after_bound` and `not_before_bound` role fields. [[GH-3031](https://github.com/openbao/openbao/pull/3031)]
* secrets/pki: `/sign-verbatim` now preserves the original subject encoding from the CSR. Previously, UTF8String values were re-encoded as PrintableString when the subject contained only ASCII characters. [[GH-2861](https://github.com/openbao/openbao/pull/2861)]
* openapi: Add support for reporting SCAN on endpoints. [[GH-2902](https://github.com/openbao/openbao/pull/2902)]

DEPRECATIONS:

* core/seal: Following the introduction of pluggable Auto Unseal support in this release, the built-in versions of the `alicloudkms`, `awskms`, `azurekeyvault`, `gcpckms`, `ocikms` and `pkcs11` Auto Unseal mechanisms will be removed in v2.7.0 and remain available as external plugins only. [[GH-2586](https://github.com/openbao/openbao/pull/2586)]
* physical/file: Deprecate file storage backend for removal in v2.7.0. [[GH-2849](https://github.com/openbao/openbao/pull/2849)]
* packaging, seal/pkcs11: Following the introduction of pluginized HSM/PKCS#11 Auto Unseal support in this release, the HSM distribution of OpenBao will be discontinued by v2.7.0. PKCS#11 support remains available via the PKCS#11 plugin which can be used together with the standard distribution of OpenBao. [[GH-2586](https://github.com/openbao/openbao/pull/2586)]
* packaging: Drop builds for 32-bit ARM Windows as part of its [removal from Go 1.26](https://go.dev/doc/go1.26#windows). [[GH-3191](https://github.com/openbao/openbao/pull/3191)]
* packaging/container: Architecture-specific container image tags such as `openbao/openbao:2.6.0-arm64` will not be published starting with this release. Refer to multi-arch container images instead (simply `openbao/openbao:2.6.0`). [[GH-3209](https://github.com/openbao/openbao/pull/3209)]

## 2.5.5
## June 17, 2026

SECURITY:

* auth/ldap: Prevent unlikely post-bind LDAP injection via bind DN to group resolution. GHSA-6mwx-4547-5vc9. [[GH-3306](https://github.com/openbao/openbao/pull/3306)]
* secrets/ldap: Prevent potential LDAP injection with unsanitized DNs for service accounts. GHSA-6mwx-4547-5vc9. [[GH-3306](https://github.com/openbao/openbao/pull/3306)]
* secrets/transit: Prevent server crash due to unlock of unlocked mutex for RSA keys created with `derived=true`. GHSA-8w8f-r2xv-4q4j. [[GH-3309](https://github.com/openbao/openbao/pull/3309)]
* core/leases: Fix unauthorized cross-namespace lease revocation via leaked lease identifiers. GHSA-c36x-h252-g9x2. [[GH-3307]](https://github.com/openbao/openbao/pull/3307)
* core/namespaces: Fix namespace path canonicalization of "root" enabling unauthorized operations on the parent namespace. GHSA-mwr2-wmgp-crj6. [[GH-3308]](https://github.com/openbao/openbao/pull/3308)

BUG FIXES:

* core/ha: Return to read-enabled standby mode instead of read-disabled standby mode after stepping down from active mode when standby reads are enabled. This also fixes SIGHUPs crashing standby nodes if they've previously stepped down from active. [[GH-3223](https://github.com/openbao/openbao/pull/3223)]
* auth/mfa: Correctly forward two-phase MFA validations on standby nodes. [[GH-3246](https://github.com/openbao/openbao/pull/3246)]
* sys/namespaces: Support clearing a namespace's `custom_metadata` by providing a patch that sets `custom_metadata` to `null` at the top-level. [[GH-3273](https://github.com/openbao/openbao/pull/3273)]
* sys/plugins: Fix `/sys/plugins/catalog` and `/sys/plugins/catalog/<type>` not returning versioned plugins. [[GH-3186](https://github.com/openbao/openbao/pull/3186)]

## 2.5.4
## May 20, 2026

SECURITY:

* core/auth: Fix audit logs dropping custom headers when using inline auth. GHSA-q8cj-789h-vg24 / CVE-2026-46358. [[GH-3076](https://github.com/openbao/openbao/pull/3076)]
* core: Prevent hidden default token issuance from auth plugin endpoints returning both a `logical.Auth{}` response object and an error. GHSA-7j6w-vvw2-5f9c / CVE-2026-46405. [[GH-3150](https://github.com/openbao/openbao/pull/3150)]
* core: Remove legacy lease endpoints (`sys/revoke`, `sys/renew`, `sys/revoke-prefix`, and `sys/revoke-force`) due to cross-namespace lease modification. GHSA-v8v8-cm84-m686 / CVE-2026-45808. [[GH-3152](https://github.com/openbao/openbao/pull/3152)]

IMPROVEMENTS:

* storage/postgresql: Set constraint name to `table+"_pkey"` and `ha_table+"_pkey"` and index to `table+"_idx"` for uniqueness when reusing the same database partition for multiple OpenBao instances. [[GH-2876](https://github.com/openbao/openbao/pull/2876)]

BUG FIXES:

* auth/kerberos: Do not return `logical.Auth{}` response during initial negotiation at the same time as an error. [[GH-3150](https://github.com/openbao/openbao/pull/3150)]
* core/mfa: Handle invalidation for login MFA, ensuring standby nodes respond appropriately on writes. [[GH-3083](https://github.com/openbao/openbao/pull/3083)]
* core/policies: Fix `list_scan_response_keys_filter_path` incorrectly erring on empty list responses. [[GH-3063](https://github.com/openbao/openbao/pull/3063)]
* core/quotas: Correctly handle default rate limit exempt paths on quota configuration invalidation. [[GH-2953](https://github.com/openbao/openbao/pull/2953)]
* core: Disallow logical secret engines from creating authentication tokens. [[GH-3087](https://github.com/openbao/openbao/pull/3087)]
* core: Forward generate-root, step-down and rekey requests to active node to resolve inconsistent standby behavior. [[GH-3006](https://github.com/openbao/openbao/pull/3006)]
* storage/raft: Wait for autopilot shutdown to avoid panic when racing to retrieve known servers. [[GH-3054](https://github.com/openbao/openbao/pull/3054)]
* storage/postgresql: Revert accidental rename of `ha_table` option to `haTable`. Both spellings are now supported to retain compatibility, though `ha_table` takes precedence. [[GH-2876](https://github.com/openbao/openbao/pull/2876)]

## 2.5.3
## April 20, 2026

SECURITY:

* auth/cert: Prevent token renewal with different-but-valid certificate. GHSA-7ccv-rp6m-rffr / CVE-2026-39388. [[GH-2932](https://github.com/openbao/openbao/pull/2932)]
* auth/token: Prevent cross-namespace token renewal, revocation by accessor. GHSA-p49j-v9wc-wg57 / CVE-2026-40264. [[GH-2934](https://github.com/openbao/openbao/pull/2934)]
* core: Disallow `sys/generate-root/*` by default due to unauthenticated cancellation; use `disable_unauthed_generate_root_endpoints=false` to temporarily re-enable. Upstream HCSEC-2026-08 / CVE-2026-5807. [[GH-2912](https://github.com/openbao/openbao/pull/2912)]
* core: Forbid request path traversal using `.` and `..` segments by default. If required, set the `unsafe_relative_paths`. Upstream HCSEC-2026-05 / CVE-2026-3605. [[GH-2910](https://github.com/openbao/openbao/pull/2910)]
* core/plugins: Validate and restrict downloaded plugin binary size from OCI images; set `plugin_download_max_size` to limit the size (defaults to 512MB). GHSA-r65v-xgwc-g56j / CVE-2026-39396. [[GH-2941](https://github.com/openbao/openbao/pull/2941)]
* core/namespaces: Ensure lease revocation on namespace re-deletion. GHSA-vv66-6rp4-wr4f. [[GH-2935](https://github.com/openbao/openbao/pull/2935)]
* database/postgresql: Correctly quote schema name in revoke statement. GHSA-6vgr-cp5c-ffx3 / CVE-2026-39946. [[GH-2931](https://github.com/openbao/openbao/pull/2931)]

BUG FIXES:

* command/server: Refuse repeated startup if self-initialization failed on initial run. [[GH-2908](https://github.com/openbao/openbao/pull/2908)]
* core: Fix namespace invalidation on standby when disable_cache=true is set. [[GH-2822](https://github.com/openbao/openbao/pull/2822)]
* core: Loosen overly strict check for view path check, strictly forbidding `..` as a substring within path segments. [[GH-2910](https://github.com/openbao/openbao/pull/2910)]
* secret/database, secret/openldap, secret/rabbitmq: Fix dynamic secret requests failing with an "Internal Server Error" on standby nodes [[GH-2853](https://github.com/openbao/openbao/pull/2853)]

## 2.5.2
## March 25, 2026

SECURITY:

* auth/jwt: Prevent XSS via `error_description` parameter in `callback_mode=direct` auth methods. CVE-2026-33758. [[GH-2709](https://github.com/openbao/openbao/pull/2709)]
* auth/jwt: Prompt for confirmation during direct callback mode to authorize OpenBao token issuance. CVE-2026-33757. [[GH-2710](https://github.com/openbao/openbao/pull/2710)]

BUG FIXES:

* command: External token helpers now inherit environment variables from the parent process. [[GH-2570](https://github.com/openbao/openbao/pull/2570)]
* core/metrics: Fix count of leases/tokens/kv-secrets/entities metric not being emitted. [[GH-2672](https://github.com/openbao/openbao/pull/2672)]
* core/mounts, core/namespaces: Fix lock ordering in mount deletion racing against namespace updates, causing deadlocks. [[GH-2625](https://github.com/openbao/openbao/pull/2625)]
* core/seal: Fix `/sys/rotate/root` call rotating both root key and unseal key when using a Shamir Seal, losing all key shares. [[GH-2619](https://github.com/openbao/openbao/pull/2619)]
* core: Skip re-scheduling lease expiration jobs that need to write to storage when a node unseals in read-only mode. [[GH-2549](https://github.com/openbao/openbao/pull/2549)]
* core: Fix potential deadlock in JobManager, which can cause mount deletion timeouts. [[GH-2630](https://github.com/openbao/openbao/pull/2630)]
* http: Forward help requests to active node when unable to handle them on standby with read requests handling disabled. [[GH-2572](https://github.com/openbao/openbao/pull/2572)]
* identity/oidc: Fix OIDC named key rotation silently skipping in non-root namespaces due to double namespace prefix in storage path lookup. [[GH-2669](https://github.com/openbao/openbao/pull/2669)]
* raft: Propagate peer join/remove/promote/demote and autopilot read/update requests to active node. [[GH-2574](https://github.com/openbao/openbao/pull/2574)]

## 2.5.1
## February 23, 2026

SECURITY:

* Build with Go 1.25.7 to resolve CVE-2025-68121 / GO-2026-4337. [[GH-2426](https://github.com/openbao/openbao/pull/2426)]
* Bump go.opentelemetry.io/otel/sdk to 1.40.0 to resolve CVE-2026-24051 / GO-2026-4394 / GHSA-9h8m-3fm2-qjrq. [[GH-2518](https://github.com/openbao/openbao/pull/2518)]

BUG FIXES:

* seal: Fix Auto Unseal failing when upgrading to v2.5.0 or downgrading from v2.5.0 to an earlier version. This affected the following providers: AliCloud KMS, AWS KMS, Azure Key Vault, GCP Cloud KMS & OCI KMS. [[GH-2505](https://github.com/openbao/openbao/pull/2505)]
* core/mounts: Don't attempt to upgrade legacy mount tables when in read-only standby mode. [[GH-2467](https://github.com/openbao/openbao/pull/2467)]
* core/expiration: Fix total lease count not being decremented when revoking irrevocable leases. [[GH-2414](https://github.com/openbao/openbao/pull/2414)]
* pki: Fix "context canceled" issue when processing cache invalidation, leading to pki returning 500 until reload. [[GH-2472](https://github.com/openbao/openbao/pull/2472)]
* command: Fix panic when the home directory cannot be trivially deduced via environment variables. [[GH-2446](https://github.com/openbao/openbao/pull/2446)]

CHANGES:

* core/identity: Remove pre-v2.5.0 corrupt namespace identity groups during unseal; corrupt groups need to be recreated by an admin. Check for `deleting corrupt group` in server startup logs. [[GH-2454](https://github.com/openbao/openbao/pull/2454)]

## 2.5.0
## February 4, 2026

SECURITY:

* core/sys: BREAKING: default value of `disable_unauthed_rekey_endpoints` is `true`, to continue using unauthed rekey endpoints, set `disable_unauthed_rekey_endpoints=false` in listeners explicitly. [[GH-2125](https://github.com/openbao/openbao/pull/2125)]

CHANGES:

* Remove the deprecated `creation_statements`, `revocation_statements`, `rollback_statements`, and `renew_statements` fields from the dbplugin `Statements` protobuf message [[GH-1962](https://github.com/openbao/openbao/pull/1962)]
* api: The deprecated api.MountConfigOutput.PluginName field was removed. This was already always empty. [[GH-2036](https://github.com/openbao/openbao/pull/2036)]
* auth/jwt: Return error msg on `OIDCDiscoveryURL` including `.well-known/openid-configuration` component. [[GH-2066](https://github.com/openbao/openbao/pull/2066)]
* core/audit: removed `jsonx` as a output format option for audit mounts [[GH-2047](https://github.com/openbao/openbao/pull/2047)]
* sys/host-info: This endpoint may start reporting slightly higher memory usage than before (On Linux only). See https://github.com/shirou/gopsutil/releases/tag/v4.25.8 for more information. [[GH-1887](https://github.com/openbao/openbao/pull/1887)]

FEATURES:

* Add **declarative plugin distribution via OCI images**: using the `plugin` configuration keyword.
  - Plugins can be automatically downloaded via the `plugin_auto_download=true` option.
  - Plugins can be manually downloaded via the `bao plugin init` command.
  - Plugins can be automatically registered via the `plugin_auto_register=true` option, regardless if they were manually provisioned or from OCI images. [[GH-1824](https://github.com/openbao/openbao/pull/1824)]
* Support **Horizontal Read Scalability**: all existing HA standby nodes are automatically upgraded with read support.
  - Requests which only perform storage read operations will be handled locally on the standby node.
  - Requests which perform a storage write operation (or as indicated by plugins) are forwarded to the active leader.
  - Results are eventually consistent: a write may not be immediately visible on the standby.
  - To disable, set `disable_standby_reads=true` in the config file before startup. [[GH-1986](https://github.com/openbao/openbao/pull/1986)]
* **OIDC Provider**: Add Client Credentials flow to OIDC Provider. [[GH-1732](https://github.com/openbao/openbao/pull/1732)]
* **sdk/framework**: add `Response.SchemaName` to allow custom response schema names in the generated OpenAPI spec. [[GH-1714](https://github.com/openbao/openbao/pull/1714)]

IMPROVEMENTS:

* audit: Add http audit device for low-volume, webhook-based audit event reporting. [[GH-1709](https://github.com/openbao/openbao/pull/1709)]
* auth/jwt: Add type checking to role. [[GH-1854](https://github.com/openbao/openbao/pull/1854)]
* command: Add environment variables to provide configuration for Proxy, Agent, and `bao operator migrate` via `BAO_PROXY_CONFIG_PATH`, `BAO_AGENT_CONFIG_PATH`, and `BAO_MIGRATE_CONFIG_PATH`. [[GH-2153](https://github.com/openbao/openbao/pull/2153)]
* command: Support `BAO_CONFIG_PATH` in `plugin init`, just like `server` &c do. [[GH-2164](https://github.com/openbao/openbao/pull/2164)]
* command: `server`, `operator diagnose` and 'operator validate-config` now support the environment variable BAO_CONFIG_FILE for the -config command option. [[GH-2115](https://github.com/openbao/openbao/pull/2115)]
* core/metrics: Support custom path for metrics on metrics-only listeners. [[GH-1853](https://github.com/openbao/openbao/pull/1853)]
* core/namespaces: Use JobManager for namespace deletion, decreasing lock contention. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* core/policies: Add endpoint to allow detailed listing of a subset of policies. [[GH-1965](https://github.com/openbao/openbao/pull/1965)]
* core/policies: Use per-namespace write lock, improving parallelism. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* core: Added `metrics_only` and `disallow_metrics` options to control metrics endpoint exposure on a per-listener basis. [[GH-1834](https://github.com/openbao/openbao/pull/1834)]
* database/valkey: Adds the ability to configure the Valkey database connection using a single connection_url parameter. [[GH-1923](https://github.com/openbao/openbao/pull/1923)]
* database: all database plugins now ignore "not found" errors on revoke by default. See [Plugin Author Guide](https://openbao.org/docs/plugins/plugin-authors-guide/#revoke-operations-should-ignore-not-found-errors) for rationale. [[GH-2101](https://github.com/openbao/openbao/pull/2101)]
* openapi: Add response schemas for token store operations and update operation suffixes. [[GH-1840](https://github.com/openbao/openbao/pull/1840)]
* pki: add `allowed_ip_sans_cidr` parameter to PKI role system, to provide additional checks for IP SANs. [[GH-1833](https://github.com/openbao/openbao/pull/1833)]
* storage/postgresql: implement `physical.FencingHABackend` to minimize chances that writes on secondary nodes occur. [[GH-1571](https://github.com/openbao/openbao/pull/1571)]
* transit: Add associated_data parameter to generate data key. [[GH-1828](https://github.com/openbao/openbao/pull/1828)]
* website: Add an example of current role statement from Valkey. [[GH-1811](https://github.com/openbao/openbao/pull/1811)]

DEPRECATIONS:

* core/seal: Remove the undocumented "aead" seal mechanism. Consider switching to the static seal instead as a replacement. [[GH-1910](https://github.com/openbao/openbao/pull/1910)]
* core: Removed `FeatureFlags` parsing and related code. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]
* sdk: Removed `sdk/v2/helper/license` package. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]
* ui: Removed `internal/ui/feature-flags` endpoint and all its usage. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]

BUG FIXES:

* agent/auth: Fix token reissue error with kerberos method. [[GH-2373](https://github.com/openbao/openbao/pull/2373)]
* auth/jwt: Fix ordering of variable declarations in CEL program roles. [[GH-1854](https://github.com/openbao/openbao/pull/1854)]
* core/identity: Ensure periodic func only operates on a single namespace at a time, decreasing storage contention. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* core/identity: fix corrupt data being stored when referencing `member_group_ids` across namespaces (requires `unsafe_cross_namespace_identity=true`) [[GH-2321](https://github.com/openbao/openbao/pull/2321)]
* core/namespaces: Ensure namespace creation is interruptible, allowing namespace deletion for cleanup. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* core/namespaces: Fix deadlock on namespace creation, deletion due to transaction/lock ordering. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* core/namespaces: Fix storage failures in namespace creation leading to a total system deadlock. [[GH-2166](https://github.com/openbao/openbao/pull/2166)]
* core/namespaces: improve recovery from partial deletion of namespaces, preventing server startup failure. [[GH-2188](https://github.com/openbao/openbao/pull/2188)]
* database/valkey: The creation_statements parameter now correctly accepts a standard array of strings for ACL rules (e.g., `["+@read", "~*"]`). Previously, it incorrectly required a stringified JSON array. The old format is still supported for backward compatibility. [[GH-1959](https://github.com/openbao/openbao/pull/1959)]
* helper/jobmanager: Fix queue length metrics to report as gauges. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* physical/postgresql: ensure underlying HA lock removal from database causes lock loss, write failures. [[GH-2100](https://github.com/openbao/openbao/pull/2100)]
* raft: return correct raft leader id from read replica nodes when using `bao operator raft list-peers`. [[GH-2331](https://github.com/openbao/openbao/pull/2331)]
* sdk/logical: Use created transaction for `WithTransaction` callback. [[GH-2226](https://github.com/openbao/openbao/pull/2226)]
* secrets/pki: Fix ordering of variable declarations in CEL program roles. [[GH-1854](https://github.com/openbao/openbao/pull/1854)]

## 2.5.0-beta20251125
## November 25, 2025

SECURITY:

* core/sys: BREAKING: default value of `disable_unauthed_rekey_endpoints` is `true`, to continue using unauthed rekey endpoints, set `disable_unauthed_rekey_endpoints=false` in listeners explicitly. [[GH-2125](https://github.com/openbao/openbao/pull/2125)]

CHANGES:

* sdk: Remove the deprecated `creation_statements`, `revocation_statements`, `rollback_statements`, and `renew_statements` fields from the dbplugin `Statements` protobuf message. [[GH-1962](https://github.com/openbao/openbao/pull/1962)]
* api: The deprecated api.MountConfigOutput.PluginName field was removed. This was already always empty. [[GH-2036](https://github.com/openbao/openbao/pull/2036)]
* auth/jwt: Return error msg on OIDCDiscoveryURL including '.well-known/openid-configuration' component. [[GH-2066](https://github.com/openbao/openbao/pull/2066)]
* core/audit: removed `jsonx` as an output format option for audit mounts. [[GH-2047](https://github.com/openbao/openbao/pull/2047)]
* sys/host-info: This endpoint may start reporting slightly higher memory usage than before (On Linux only). See https://github.com/shirou/gopsutil/releases/tag/v4.25.8 for more information. [[GH-1887](https://github.com/openbao/openbao/pull/1887)]

FEATURES:

* Add **declarative plugin distribution via OCI images**: using the `plugin` configuration keyword.
  - Plugins can be automatically downloaded via the `plugin_auto_download=true` option.
  - Plugins can be manually downloaded via the `bao plugin init` command.
  - Plugins can be automatically registered via the `plugin_auto_register=true` option, regardless if they were manually provisioned or from OCI images. [[GH-1824](https://github.com/openbao/openbao/pull/1824)]
* Support **Horizontal Read Scalability**: all existing HA standby nodes are automatically upgraded with read support.
  - Requests which only perform storage read operations will be handled locally on the standby node.
  - Requests which perform a storage write operation (or as indicated by plugins) are forwarded to the active leader.
  - Results are eventually consistent: a write may not be immediately visible on the standby.
  - To disable, set `disable_standby_reads=true` in the config file before startup. [[GH-1986](https://github.com/openbao/openbao/pull/1986)]
* core/identity: Add Client Credentials flow to OIDC Provider. [[GH-1732](https://github.com/openbao/openbao/pull/1732)]

IMPROVEMENTS:

* audit: Add http audit device for low-volume, webhook-based audit event reporting. [[GH-1709](https://github.com/openbao/openbao/pull/1709)]
* auth/jwt: Add type checking to role. [[GH-1854](https://github.com/openbao/openbao/pull/1854)]
* command: `server`, `operator diagnose` and `operator validate-config` now support
the environment variable BAO_CONFIG_FILE for the -config command option. [[GH-2115](https://github.com/openbao/openbao/pull/2115)]
* core/metrics: Support custom path for metrics on metrics-only listeners. [[GH-1853](https://github.com/openbao/openbao/pull/1853)]
* core/policies: Add endpoint to allow detailed listing of a subset of policies. [[GH-1965](https://github.com/openbao/openbao/pull/1965)]
* core: Added `metrics_only` and `disallow_metrics` options to control metrics endpoint exposure on a per-listener basis. [[GH-1834](https://github.com/openbao/openbao/pull/1834)]
* database/valkey: Adds the ability to configure the Valkey database connection using a single connection_url parameter. [[GH-1923](https://github.com/openbao/openbao/pull/1923)]
* database: All database plugins now ignore "not found" errors on revoke by default. See [Plugin Author Guide](https://openbao.org/docs/plugins/plugin-authors-guide/#revoke-operations-should-ignore-not-found-errors) for rationale. [[GH-2101](https://github.com/openbao/openbao/pull/2101)]
* openapi: Add response schemas for token store operations and update operation suffixes. [[GH-1840](https://github.com/openbao/openbao/pull/1840)]
* pki: Add `allowed_ip_sans_cidr` parameter to PKI role system, to provide additional checks for IP SANs. [[GH-1833](https://github.com/openbao/openbao/pull/1833)]
* storage/postgresql: Implement `physical.FencingHABackend` to minimize chances that writes on secondary nodes occur. [[GH-1571](https://github.com/openbao/openbao/pull/1571)]
* transit: Add associated_data parameter to generate data key. [[GH-1828](https://github.com/openbao/openbao/pull/1828)]
* sdk/framework: Add Response.SchemaName to allow custom response schema names in the generated OpenAPI spec. [[GH-1714](https://github.com/openbao/openbao/pull/1714)]

DEPRECATIONS:

* core/seal: Remove the undocumented "aead" seal mechanism. Consider switching to the [static seal](https://openbao.org/docs/configuration/seal/static) instead as a replacement. [[GH-1910](https://github.com/openbao/openbao/pull/1910)]
* core: Remove `FeatureFlags` parsing and related code. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]
* sdk: Remove `sdk/v2/helper/license` package. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]
* ui: Remove `internal/ui/feature-flags` endpoint and all its usage. [[GH-2045](https://github.com/openbao/openbao/pull/2045)]

BUG FIXES:

* auth/jwt: Fix ordering of variable declarations in CEL program roles [[GH-1854](https://github.com/openbao/openbao/pull/1854)]
* secrets/pki: Fix ordering of variable declarations in CEL program roles [[GH-1854](https://github.com/openbao/openbao/pull/1854)]
* database/valkey: The creation_statements parameter now correctly accepts a standard array of strings for ACL rules (e.g., ["+@read", "~*"]). Previously, it incorrectly required a stringified JSON array. The old format is still supported for backward compatibility. [[GH-1959](https://github.com/openbao/openbao/pull/1959)]
* physical/postgresql: Ensure underlying HA lock removal from database causes lock loss, write failures [[GH-2100](https://github.com/openbao/openbao/pull/2100)]
* seal/pkcs11: Remove strict requirement of key label. (https://github.com/openbao/go-kms-wrapping/pull/56)

## 2.4.4
## November 24, 2025

SECURITY:

* core/identity: Correctly lowercase policy names on identity groups to prevent root policy assignment. CVE-2025-64761 / GHSA-7ff4-jw48-3436. Second part of upstream's HCSEC-2025-13 / CVE-2025-5999. [[GH-2143](https://github.com/openbao/openbao/pull/2143)]

IMPROVEMENTS:

* command: `operator diagnose` certificate expiration warnings are now raised if less than 15% of the certificate's validity period remains. Previously, any certificate that was set to expire in the next 30 days would be flagged. This made little sense for short-lived certificates. [[GH-2062](https://github.com/openbao/openbao/pull/2062)]

BUG FIXES:

* auth/cert: allow use of always-fresh OCSP servers which elide NextUpdate [[GH-2079](https://github.com/openbao/openbao/pull/2079)]
* auth/jwt: Fix token renewal of pre-v2.3.x JWT tokens and all OIDC tokens after CEL support was introduced. [[GH-2148](https://github.com/openbao/openbao/pull/2148)]
* command: `operator diagnose` certificate expiration warnings now contain the correct time to expiration. [[GH-2062](https://github.com/openbao/openbao/pull/2062)]
* command: `operator diagnose` now correctly ignores trailing data in certificate files. [[GH-2065](https://github.com/openbao/openbao/pull/2065)]
* command: `operator diagnose` now correctly verifies intermediate certs if no root certs are supplied. [[GH-2065](https://github.com/openbao/openbao/pull/2065)]
* command: pki health check error now contains actual mount path instead of a template placeholder. [[GH-2061](https://github.com/openbao/openbao/pull/2061)]
* core: fix nil panic in the rare case were an expiration retry is running during shutdown [[GH-2019](https://github.com/openbao/openbao/pull/2019)]
* raft: fix memory leak when using only non-transactional operations. This was a regression introduced in release 2.4.2 with #1889. [[GH-2067](https://github.com/openbao/openbao/pull/2067)]
* sdk/helper/ocsp: allow use of always-fresh OCSP servers which elide NextUpdate [[GH-2079](https://github.com/openbao/openbao/pull/2079)]

## 2.4.3
## October 22, 2025

SECURITY:

* audit: redact `HTTPRawBody` response parameter in audit logs; CVE-2025-62513 / GHSA-ghfh-fmx4-26h8. [[GH-2002](https://github.com/openbao/openbao/pull/2002)]
* audit: redact `[]byte` type response parameters in audit logs; CVE-2025-62705 / GHSA-rc54-2g2c-g36g. [[GH-2002](https://github.com/openbao/openbao/pull/2002)]

IMPROVEMENTS:

* core/namespaces: Setting the `X-Vault-Namespace` Header (or the `BAO_NAMESPACE` environment variable when using the cli) to "root" now maps to the root namespace. [[GH-1918](https://github.com/openbao/openbao/pull/1918)]

BUG FIXES:

* core/identity: Entities timestamps are now correctly formatted in `RFC3339Nano`, as previously done so. [[GH-1873](https://github.com/openbao/openbao/pull/1873)]
* core/namespaces: Fix mount creation failing if mount name is equal to the name of the containing namespace [[GH-1958](https://github.com/openbao/openbao/pull/1958)]
* core/namespaces: ensure interrupted namespace creation fails gracefully; prevents identity store panic and partial memory-only namespaces [[GH-1990](https://github.com/openbao/openbao/pull/1990)]
* core/namespaces: only report namespaces which the provided token has access to from `sys/internal/ui/namespaces` [[GH-1982](https://github.com/openbao/openbao/pull/1982)]
* raft: fix memory leak on standby nodes [[GH-1889](https://github.com/openbao/openbao/pull/1889)]
* sdk/framework: Reduce memory usage of repeated mounts through singleton pattern regex cache [[GH-1893](https://github.com/openbao/openbao/pull/1893)]
* secrets/kv: KV entries timestamps are now correctly formatted in `RFC3339Nano`, as previously done so. [[GH-1872](https://github.com/openbao/openbao/pull/1872)]

## 2.4.1
## September 11, 2025

SECURITY:

* http: Limit the complexity of JSON in HTTP request bodies through max_request_json_memory and max_request_json_strings. HCSEC-2025-24 / CVE-2025-6203 / CVE-2025-59043. [[GH-1756](https://github.com/openbao/openbao/pull/1756)]

BUG FIXES:

* auth/jwt: Add missing OIDC flow in JWK validator construction [[GH-1779](https://github.com/openbao/openbao/pull/1779)]
* auth/jwt: Support token renewal with CEL roles. [[GH-1776](https://github.com/openbao/openbao/pull/1776)]
* auth/mfa: Allow single-flow MFA to work with inline authentication. [[GH-1753](https://github.com/openbao/openbao/pull/1753)]
* auth/mfa: Correctly persist tokens created through two-step MFA login enforcement. [[GH-1753](https://github.com/openbao/openbao/pull/1753)]
* command: fix `operator init` not allowing for 0 as `recovery_shares` value. [[GH-1754](https://github.com/openbao/openbao/pull/1754)]
* command: fix `operator rotate-keys` not returning recovery keys when server is initialized with 0 `recovery_shares`. [[GH-1754](https://github.com/openbao/openbao/pull/1754)]

## 2.4.0
## August 28, 2025

SECURITY:

* audit/file: Restrict `mode` parameter
  - Refuse setting an [irregular](https://pkg.go.dev/io/fs#FileMode.IsRegular) file mode
  - Silently strip any executable bits [[GH-1651](https://github.com/openbao/openbao/pull/1651)]

CHANGES:

* `certutil.ParsePublicKeyPEM` of the package `github.com/openbao/openbao/sdk/v2/helper/certutil` will now return a `crypto.PublicKey` instead of `any`. You might need to remove type assertions from your code. [[GH-1611](https://github.com/openbao/openbao/pull/1611)]
* database: Drop obsolete upgrade check in `roleAtPath()` function introduced in `v0.10` of Vault. [[GH-1675](https://github.com/openbao/openbao/pull/1675)]
* sdk/framework: Remove `LegacyStringToSliceHookFunc`, use `mapstructure.StringToWeakSliceHookFunc` instead. [[GH-1626](https://github.com/openbao/openbao/pull/1626)]
* sdk/helper: Removed `sdk/helper/base62`, `sdk/helper/mlock`, `sdk/helper/parseutil`, `sdk/helper/password`, `sdk/helper/strutil`, and `sdk/helper/tlsutil` packages.
   -  Please use `github.com/openbao/go-secure-stdlib/xxx` or `github.com/hashicorp/go-secure-stdlib/xxx` instead.
* sdk/database/helper/connutil: Removed `Initialize` from `ConnectionProducer` interface, and `SQLConnectionProducer` struct. [[GH-1676](https://github.com/openbao/openbao/pull/1676)]
* sdk/logical: Introduce context to logical.HandleListPage(...). [[GH-1696](https://github.com/openbao/openbao/pull/1696)]
* sdk: Bump Go version to 1.24.0 [[GH-1690](https://github.com/openbao/openbao/pull/1690)]
* vault/seal: removal of deprecated migration path of an old pre-Vault v1.0 (encrypted) recovery config location [[GH-1424](https://github.com/openbao/openbao/pull/1424)]

FEATURES:

* **Allow filtering LIST, SCAN responses** via the `list_scan_response_keys_filter_path` parameter to restrict information to only readable or listable values. [[GH-1389](https://github.com/openbao/openbao/pull/1389)]
* **Configuration-Based Audit Devices**: Create and remove audit devices through server configuration updates. Changes are applied on restart and SIGHUP with issues appearing in the logs. [[GH-1700](https://github.com/openbao/openbao/pull/1700)]
* **Declarative Self-Initialization**: allow server operators to define initial
  service state through request-driven initialization that occurs
  automatically on first server start. Operators can reference environment
  variables and files to provision initial authentication, audit, and secret
  mounts in addition to having full control over general requests to OpenBao
  It is suggested to put the minimal necessary configuration in this and use
  a proper IaC platform like OpenTofu to perform further configuration of the
  instance. [[GH-1506](https://github.com/openbao/openbao/pull/1506)]
* **Delay recovery key generation for auto-unseal mechanisms and make rotation authenticated**:
  Add authenticated root and recovery key rotation endpoints, allow
  delayed recovery key generation (setting initial shares to 0).
  Solve the issue with the unauthenticated recovery key rotation APIs. [[GH-1518](https://github.com/openbao/openbao/pull/1518)]
* **Inline, Write-less Authentication**: support passing authentication
  information inline with the desired main operation to avoid the need
  for separate authentication calls, storing and maintaining tokens. This
  authentication form will not work with operations that create leases.
  In this form of authentication, no storage writes occur as a result of
  authentication allowing its use on future read-enabled standby nodes. [[GH-1433](https://github.com/openbao/openbao/pull/1433)]
* Add **static key unseal mechanism** to allow auto-unseal in environments with explicit trust chaining. [[GH-1425](https://github.com/openbao/openbao/pull/1425)]

IMPROVEMENTS:

* api/auth/jwt: initial implementation of JWT Auth Method [[GH-1526](https://github.com/openbao/openbao/pull/1526)]
* auth/oidc: Add new `show_qr=true` cli option to display a QR code of the login URL. [[GH-1561](https://github.com/openbao/openbao/pull/1561)]
* auto-unsealing: Improved the clarity of the warning message logged when the server is uninitialized and auto-unsealing is configured. [[GH-1411](https://github.com/openbao/openbao/pull/1411)]
* builtin/credential/jwt: Support TLS authentication against explicit alt name/subject. [[GH-1533](https://github.com/openbao/openbao/pull/1533)]
* cel: Add cel-go ext helpers for string, list, optional, regex, math, set, and encoder operations [[GH-1697](https://github.com/openbao/openbao/pull/1697)]
* cel: Unify CEL helper functions between JWT and PKI modules, making email validation and other utilities available across both authentication and certificate management [[GH-1697](https://github.com/openbao/openbao/pull/1697)]
* cli: add new subcommand "bao operator validate-config" to validate a configuration file syntax [[GH-1609](https://github.com/openbao/openbao/pull/1609)]
* core: sys/seal-status: endpoint now always returns the barrier seal type, explicitly adds recovery seal type [[GH-1638](https://github.com/openbao/openbao/pull/1638)]
* deps: Update go-jose v3 to go-jose v4 [[GH-1477](https://github.com/openbao/openbao/pull/1477)]
* secrets/kv: Add CAS (Compare-And-Swap) support for metadata operations in KV v2 secrets engine. Metadata updates now support versioning via `metadata_cas` parameter and `metadata_cas_required` configuration option to prevent concurrent modification conflicts. [[GH-1372](https://github.com/openbao/openbao/pull/1372)]
* ui: change the message 'Vault is sealed to 'OpenBao is Sealed' by changing the title of the unseal template [[GH-1652](https://github.com/openbao/openbao/pull/1652)]
* seal/pkcs11: Support and default to software encryption for RSA key types. [[GH-1742](https://github.com/openbao/openbao/pull/1742)]

DEPRECATIONS:

* storage/postgresql: remove support for legacy PostgreSQL versions before 9.5 which require a special upsert function. [[GH-1570](https://github.com/openbao/openbao/pull/1570)]

BUG FIXES:

* api: Fix compatibility with sys/health from Vault Enterprise [[GH-1730](https://github.com/openbao/openbao/pull/1730)]
* command: fixes typo in Windows command for setting BAO_ADDR in development mode [[GH-1527](https://github.com/openbao/openbao/pull/1527)]
* core/namespaces: Prevent infinite loop in namespace loading due to incorrect list pagination when more than 100 sibling namespaces exist under a given parent [[GH-1696](https://github.com/openbao/openbao/pull/1696)]
* identity: fix nil panic when collecting metrics with unsafe_cross_namespace_identity=true. [[GH-1715](https://github.com/openbao/openbao/pull/1715)]
* pki: Truncate should error on expired certificates [[GH-1369](https://github.com/openbao/openbao/pull/1369)]
* releases: add missing container image manifests for `*-hsm` variants [[GH-1597](https://github.com/openbao/openbao/pull/1597)]
* sdk: Various constants in the `sdk` package mistakenly had no explicit type. They now now typed correctly. [[GH-1523](https://github.com/openbao/openbao/pull/1523)]
* secrets/pki: Prevent infinite loop in tidy stemming from incorrect list pagination [[GH-1696](https://github.com/openbao/openbao/pull/1696)]
* storage/postgresql: more graceful handling of parallel table creation [[GH-1506](https://github.com/openbao/openbao/pull/1506)]

## 2.3.2
## August 7, 2025

SECURITY:

* audit: Add server configuration options to disable audit mount creation via the API and to disable audit log prefixing. HCSEC-2025-14 / CVE-2025-6000 / CVE-2025-54997. [[GH-1634](https://github.com/openbao/openbao/pull/1634)]
  - `unsafe_allow_api_audit_creation (default: false)` controls the ability to create audit mounts via the API
  - `allow_audit_log_prefixing (default: false)` controls the availability of the prefix audit mount option
* auth/mfa: correctly limit reuse of TOTP codes during login MFA enforcement. HCSEC-2025-19 / CVE-2025-6015 / CVE-2025-55003. [[GH-1629](https://github.com/openbao/openbao/pull/1629)]
* auth/userpass: Prevent timing-based leak in userpass auth method. HCSEC-2025-15 / CVE-2025-6011 / CVE-2025-54999.  Assumed to also apply to HCSEC-2025-21 / CVE-2025-6010. [[GH-1628](https://github.com/openbao/openbao/pull/1628)]
* core/auth: Correctly handle alias lookahead for user lockout consistency. HCSEC-2025-16 / CVE-2025-6004 / CVE-2025-54998.
  auth/userpass: Consistently handle alias lookahead as case insensitive. HCSEC-2025-16 / CVE-2025-6004 / CVE-2025-54998.
  auth/ldap: Attempt consistent entity aliasing w.r.t. spacing and casing. HCSEC-2025-16 / CVE-2025-6004 / CVE-2025-54998 and HCSEC-2025-20 / CVE-2025-6013 / CVE-2025-55001. [[GH-1632](https://github.com/openbao/openbao/pull/1632)]
* core/identity: Correctly lowercase policy names to prevent root policy assignment. HCSEC-2025-13 / CVE-2025-5999 / CVE-2025-54996. [[GH-1627](https://github.com/openbao/openbao/pull/1627)]
* secrets/totp: Fix TOTP verification reuse bypass when the TOTP code contains spaces. HCSEC-2025-17 / CVE-2025-6014 / CVE-2025-55000. [[GH-1625](https://github.com/openbao/openbao/pull/1625)]

IMPROVEMENTS:

* core: Update to Go 1.24.6. [[GH-1637](https://github.com/openbao/openbao/pull/1637)]

BUG FIXES:

* Ignore missing mounts when deleting a namespace. This can happen when a mount is unmounted in parallel. [[GH-1594](https://github.com/openbao/openbao/pull/1594)]
* agent/template: add missing backoff mechanism for the templating server [[GH-1448](https://github.com/openbao/openbao/pull/1448)]
* core/namespaces: fixed race condition in namespace deletion operation during instance sealing [[GH-1525](https://github.com/openbao/openbao/pull/1525)]
* core/policies: fix bug with missing existing policies in namespaces during failover, startup [[GH-1613](https://github.com/openbao/openbao/pull/1613)]
* identity/oidc: Fix unintentional lowercasing of namespace accessor in assignments. [[GH-1539](https://github.com/openbao/openbao/pull/1539)]

## 2.3.1
## June 25, 2025

SECURITY:

* core/sys: Add listener parameter (`disable_unauthed_rekey_endpoints`, default: `false`) to optionally disable unauthenticated rekey operations (to `sys/rekey/*` and `sys/rekey-recovery-key/*`) for a listener. This will be set to true in a future release; see the [deprecation notice](https://openbao.org/docs/deprecation/unauthed-rekey/) for more information. Auditing is now enabled for these endpoints as well. CVE-2025-52894. Upstream HCSEC-2025-11 / CVE-2025-4656.
* sdk/framework: prevent additional information disclosure on invalid request. CVE-2025-52893. [[GH-1495](https://github.com/openbao/openbao/pull/1495)]

CHANGES:

* packaging/systemd: Do not set LimitNOFILE, allowing Go to automatically manage this value on behalf of the server. See also https://github.com/golang/go/issues/46279. [[GH-1179](https://github.com/openbao/openbao/pull/1179)]
* storage/postgresql: Support empty connection URLs to use standard component-wise variables [[GH-1297](https://github.com/openbao/openbao/pull/1297)]
* packaging: Support for Illumos removed due to broken builds [[GH-1503](https://github.com/openbao/openbao/pull/1503)]

FEATURES:

* **KMIP Auto-Unseal**: Add support for automatic unsealing of OpenBao using a KMIP protocol. [[GH-1144](https://github.com/openbao/openbao/pull/1144)]
* **Namespaces UI Support**: Added namespace UI support, including namespace picker and namespace management pages. [[GH-1406](https://github.com/openbao/openbao/pull/1406)]
* **Namespaces**: Support for tenant isolation using namespaces, application API compatible with upstream's implementation.
  - Create, read, update, delete a hierarchical directory of namespaces
  - Manage isolated per-namespace secrets engines, auth methods, tokens, policies and more
  - Migrate (remount) secrets engines and auth methods between namespaces
  - Lock and unlock namespaces
  - Route requests to namespaces via path (`/my-namespace/secrets`) or `X-Vault-Namespace` header (or both!)
  - CLI support via the `bao namespace` family of commands and the `-namespace` flag. [[GH-1165](https://github.com/openbao/openbao/pull/1165)]
* Add ARM64 HSM builds and Alpine-based HSM container images [[GH-1427](https://github.com/openbao/openbao/pull/1427)]
* Support **Common Expression Language (CEL) in PKI**. CEL allows role authors to create flexible, dynamic certificate policies with complex, custom validation support and arbitrary control over the final certificate object. [[GH-794](https://github.com/openbao/openbao/pull/794)]
* auth/jwt: Add support for Common Expression Language (CEL) login roles. CEL allows role authors to create flexible, dynamic policies with complex, custom claim validation support and arbitrary templating of `logical.Auth` data. [[GH-869](https://github.com/openbao/openbao/pull/869)]
* ssh: Support multiple certificate issuers in SSH secret engine mounts, enabling safer rotation of SSH CA key material [[GH-880](https://github.com/openbao/openbao/pull/880)]

IMPROVEMENTS:

* When using auto-unseal via KMS, KMS-specific configuration information (non-sensitive) is now logged at server startup. [[GH-1346](https://github.com/openbao/openbao/pull/1346)]
* approle: Use transactions for read + write operations [[GH-992](https://github.com/openbao/openbao/pull/992)]
* auth/jwt: Support lazy resolution of oidc_discovery_url or jwks_url when skip_jwks_validation=true is specified on auth/jwt/config; OIDC status is now reported on reading the configuration. [[GH-1306](https://github.com/openbao/openbao/pull/1306)]
* core/identity: add unsafe_cross_namespace_identity to give compatibility with Vault Enterprise's cross-namespace group membership. [[GH-1432](https://github.com/openbao/openbao/pull/1432)]
* core/policies: Add check-and-set support for modifying policies, allowing for protection against concurrent modifications. [[GH-1162](https://github.com/openbao/openbao/pull/1162)]
* core/policies: Add endpoint to allow detailed listing of policies [[GH-1224](https://github.com/openbao/openbao/pull/1224)]
* core/policies: Allow setting expiration on policies and component paths, removing policies or preventing usage of path rules after expiration. [[GH-1142](https://github.com/openbao/openbao/pull/1142)]
* core: Support pagination and transactions in ClearView, CollectKeys, and ScanView, improving secret disable memory consumption and request consistency. [[GH-1102](https://github.com/openbao/openbao/pull/1102)]
* database/valkey: Revive Redis plugin as Valkey, the OSI-licensed fork of Redis [[GH-1019](https://github.com/openbao/openbao/pull/1019)]
* database: Use transactions for read-then-write methods in the database package [[GH-995](https://github.com/openbao/openbao/pull/995)]
* pki: add not_after_bound and not_before_bound role parameters to safely limit issuance duration [[GH-1172](https://github.com/openbao/openbao/pull/1172)]
* ssh: Use transactions for read-then-write or multiple write methods in the ssh package [[GH-989](https://github.com/openbao/openbao/pull/989)]
* storage/postgresql: support retrying database connection on startup to gracefully handle service ordering issues [[GH-1280](https://github.com/openbao/openbao/pull/1280)]

DEPRECATIONS:

* Configuration of PKCS#11 auto-unseal using the duplicate and undocumented `module`, `token` and `key` options is now deprecated. Use the documented alternative options `lib`, `token_label` and `key_label` instead, respectively. ([More details](https://github.com/openbao/go-kms-wrapping/pull/33#discussion_r2112177962)) [[GH-1385](https://github.com/openbao/openbao/pull/1385)]

BUG FIXES:

* api: Stop marshaling nil interface data and adding it as a request body on an api.Request [[GH-1315](https://github.com/openbao/openbao/pull/1315)]
* core/identity: load namespace entities, groups into MemDB preventing them from disappearing on restart. [[GH-1432](https://github.com/openbao/openbao/pull/1432)]
* oidc: add some buffer time after calling oidcPeriodicFunc in test, to prevent flakiness [[GH-1178](https://github.com/openbao/openbao/pull/1178)]
* pki: addresses a timing issue revealed in pki Backend_RevokePlusTidy test [[GH-1139](https://github.com/openbao/openbao/pull/1139)]
* sealing/pkcs11: OpenBao now correctly finalizes the PKCS#11 library on shutdown (https://github.com/openbao/go-kms-wrapping/pull/32).
This is unlikely to have caused many real-world issues so far. [[GH-1349](https://github.com/openbao/openbao/pull/1349)]
* secrets/kv: Fix panic on detailed metadata list when results include a directory. [[GH-1388](https://github.com/openbao/openbao/pull/1388)]
* storage/postgresql: Remove redundant PermitPool enforced by db.SetMaxOpenConns(...). [[GH-1299](https://github.com/openbao/openbao/pull/1299)]
* storage/postgresql: skip table creation automatically on PostgreSQL replicas [[GH-1478](https://github.com/openbao/openbao/pull/1478)]
* vault: addresses a timing issue revealed in OIDC_PeriodicFunc test [[GH-1129](https://github.com/openbao/openbao/pull/1129)]
* vault: fixes a timing issue in OIDC_PeriodicFunc test [[GH-1100](https://github.com/openbao/openbao/pull/1100)]

## 2.2.2
## May 29, 2025

SECURITY:

* sdk/framework: prevent information disclosure on invalid request. HCSEC-2025-09 / CVE-2025-4166. [[GH-1323](https://github.com/openbao/openbao/pull/1323)]

BUG FIXES:

* ui: Fix description of Organizational Unit (OU) field in PKI. [[GH-1333](https://github.com/openbao/openbao/pull/1333)]

## 2.3.0-beta20250528
## May 28, 2025

SECURITY:

* sdk/framework: prevent information disclosure on invalid request. HCSEC-2025-09 / CVE-2025-4166. [[GH-1323](https://github.com/openbao/openbao/pull/1323)]

CHANGES:

* openbao: update modules and checksums to address vulnerabilities [[GH-1126](https://github.com/openbao/openbao/pull/1126)]
* packaging/systemd: Do not set LimitNOFILE, allowing Go to automatically manage this value on behalf of the server. See also https://github.com/golang/go/issues/46279. [[GH-1179](https://github.com/openbao/openbao/pull/1179)]
* storage/postgresql: Support empty connection URLs to use standard component-wise variables [[GH-1297](https://github.com/openbao/openbao/pull/1297)]

FEATURES:

* **KMIP Auto-Unseal**: Add support for automatic unsealing of OpenBao using a KMIP protocol. [[GH-1144](https://github.com/openbao/openbao/pull/1144)]
* **Namespaces**: Support for tenant isolation using namespaces, application API compatible with upstream's implementation.
  - Create, read, update, delete a hierarchical directory of namespaces
  - Manage isolated per-namespace secrets engines, auth methods, tokens, policies and more
  - Migrate (remount) secrets engines and auth methods between namespaces
  - Lock and unlock namespaces
  - Route requests to namespaces via path (`/my-namespace/secrets`) or `X-Vault-Namespace` header (or both!)
  - CLI support via the `bao namespace` family of commands and the `-namespace` flag. [[GH-1165](https://github.com/openbao/openbao/pull/1165)]
* ssh: Support multiple certificate issuers in SSH secret engine mounts, enabling safer rotation of SSH CA key material [[GH-880](https://github.com/openbao/openbao/pull/880)]

IMPROVEMENTS:

* When using auto-unseal via KMS, KMS-specific configuration information (non-sensitive) is now logged at server startup. [[GH-1346](https://github.com/openbao/openbao/pull/1346)]
* approle: Use transactions for read + write operations [[GH-992](https://github.com/openbao/openbao/pull/992)]
* auth/jwt: Support lazy resolution of oidc_discovery_url or jwks_url when skip_jwks_validation=true is specified on auth/jwt/config; OIDC status is now reported on reading the configuration. [[GH-1306](https://github.com/openbao/openbao/pull/1306)]
* core/policies: Add check-and-set support for modifying policies, allowing for protection against concurrent modifications. [[GH-1162](https://github.com/openbao/openbao/pull/1162)]
* core/policies: Add endpoint to allow detailed listing of policies [[GH-1224](https://github.com/openbao/openbao/pull/1224)]
* core/policies: Allow setting expiration on policies and component paths, removing policies or preventing usage of path rules after expiration. [[GH-1142](https://github.com/openbao/openbao/pull/1142)]
* core: Support pagination and transactions in ClearView, CollectKeys, and ScanView, improving secret disable memory consumption and request consistency. [[GH-1102](https://github.com/openbao/openbao/pull/1102)]
* database/valkey: Revive Redis plugin as Valkey, the OSI-licensed fork of Redis [[GH-1019](https://github.com/openbao/openbao/pull/1019)]
* database: Use transactions for read-then-write methods in the database package [[GH-995](https://github.com/openbao/openbao/pull/995)]
* pki: add not_after_bound and not_before_bound role parameters to safely limit issuance duration [[GH-1172](https://github.com/openbao/openbao/pull/1172)]
* ssh: Use transactions for read-then-write or multiple write methods in the ssh package [[GH-989](https://github.com/openbao/openbao/pull/989)]
* storage/postgresql: support retrying database connection on startup to gracefully handle service ordering issues [[GH-1280](https://github.com/openbao/openbao/pull/1280)]

BUG FIXES:

* api: Stop marshaling nil interface data and adding it as a request body on an api.Request [[GH-1315](https://github.com/openbao/openbao/pull/1315)]
* cli: Return a quoted string URL when -output-curl-string flag is passed in [[GH-1038](https://github.com/openbao/openbao/pull/1038)]
* oidc: add some buffer time after calling oidcPeriodicFunc in test, to prevent flakiness [[GH-1178](https://github.com/openbao/openbao/pull/1178)]
* pki: addresses a timing issue revealed in pki Backend_RevokePlusTidy test [[GH-1139](https://github.com/openbao/openbao/pull/1139)]
* sealing/pkcs11: OpenBao now correctly finalizes the PKCS#11 library on shutdown (https://github.com/openbao/go-kms-wrapping/pull/32).
  This is unlikely to have caused many real-world issues so far. [[GH-1349](https://github.com/openbao/openbao/pull/1349)]
* secrets/pki: Remove null value for subproblems encoding, fixing compatibility with certain ACME clients like certbot. [[GH-1236](https://github.com/openbao/openbao/pull/1236)]
* storage/postgresql: Remove redundant PermitPool enforced by db.SetMaxOpenConns(...). [[GH-1299](https://github.com/openbao/openbao/pull/1299)]
* ui: Fix description of Organizational Unit (OU) field in PKI. [[GH-1333](https://github.com/openbao/openbao/pull/1333)]
* vault: addresses a timing issue revealed in OIDC_PeriodicFunc test [[GH-1129](https://github.com/openbao/openbao/pull/1129)]
* vault: fixes a timing issue in OIDC_PeriodicFunc test [[GH-1100](https://github.com/openbao/openbao/pull/1100)]

## 2.2.1
## April 22, 2025

BUG FIXES:

* cli: Return a quoted string URL when -output-curl-string flag is passed in [[GH-1038](https://github.com/openbao/openbao/pull/1038)]
* openbao: update modules and checksums to address vulnerabilities [[GH-1126](https://github.com/openbao/openbao/pull/1126)]
* secrets/pki: Remove null value for subproblems encoding, fixing compatibility with certain ACME clients like certbot. [[GH-1236](https://github.com/openbao/openbao/pull/1236)]

## 2.2.0
## March 5, 2025

CHANGES:

* command/server: Prevent and warn about loading of duplicate config file from config directory. [[GH-816](https://github.com/openbao/openbao/pull/816)]
* container: Set -dev-no-store-token in default container images, fixing default read-only containers. [[GH-826](https://github.com/openbao/openbao/pull/826)]
* core/seal: remove support for legacy pre-keyring barrier entries
core/seal: remove support for legacy (direct) shamir unseal keys [[GH-750](https://github.com/openbao/openbao/pull/750)]
* core: Remove support for Solaris due to lack of Docker support. [[GH-710](https://github.com/openbao/openbao/pull/710)]

FEATURES:

* **ACME TLS Listener Certificate Provisioning**: Automatically fetch TLS certificates for OpenBao Server's TCP listeners via an Automatic Certificate Management Environment (ACME - RFC 8555) capable certificate authority (CA). This allows OpenBao to be self-hosted, using a CA contained within the instance to sign the instance's own certificates. [[GH-857](https://github.com/openbao/openbao/pull/857)]
* **PKCS#11 Auto-Unseal**: Add support for automatic unsealing of OpenBao using a PKCS#11-enabled Hardware Security Module (HSM) or Key Management System (KMS). [[GH-889](https://github.com/openbao/openbao/pull/889)]
* **Scanning**: introduce the ability to recursively list (scan) within plugins, adding a separate `scan` ACL capability, operation type, HTTP verb (`SCAN` with `GET` fallback via `?scan=true`), API, and CLI support. This also adds support to the KVv1 and KVv2 engines. [[GH-763](https://github.com/openbao/openbao/pull/763)]
* **Transit**: Add support for key derivation mechanisms (derives a new key from a base key).
   - This path uses the named base key and derivation algorithm specific parameters to derive a new named key.
   - Currently, only the ECDH key agreement algorithm is supported: the base key is one's own ECC private key and the "peer_public_key" is the pem-encoded other party's ECC public key.The computed shared secret is the resulting derived key. [[GH-811](https://github.com/openbao/openbao/pull/811)]
* **UI**: Reintroduction of the WebUI. [[GH-940](https://github.com/openbao/openbao/pull/940)]
* raft: Added support for nodes to join the Raft cluster as non-voters. [[GH-741](https://github.com/openbao/openbao/pull/741)]

IMPROVEMENTS:

* audit: modify the hashWalker to handle nested structs without panicking [[GH-887](https://github.com/openbao/openbao/pull/887)]
* auth: Use transactions for read-then-write methods in the credential package [[GH-952](https://github.com/openbao/openbao/pull/952)]
* auth: Use transactions for write and delete config for various auth methods. [[GH-878](https://github.com/openbao/openbao/pull/878)]
* core/mounts: Allow tuning HMAC request and response parameters on sys/, cubbyhole/, and identity/, enabling auditing of core policy changes. [[GH-921](https://github.com/openbao/openbao/pull/921)]
* core/policies: Allow listing policies under a given prefix. [[GH-736](https://github.com/openbao/openbao/pull/736)]
* core/policies: add `pagination_limit` to ACL policies for enforcing max pagination sizes. [[GH-802](https://github.com/openbao/openbao/pull/802)]
* core: Bump to latest Go toolchain 1.24.0. [[GH-1000](https://github.com/openbao/openbao/pull/1000)]
* identity: return alias metadata when listing entity aliases [[GH-1013](https://github.com/openbao/openbao/pull/1013)]
* rabbitmq: Use transactions for read-then-write methods in the rabbitmq package [[GH-997](https://github.com/openbao/openbao/pull/997)]
* secret/pki: Add new endpoint `pki/certs/detailed` to return detailed cert list. [[GH-680](https://github.com/openbao/openbao/pull/680)]
* secret/pki: Add pagination to `tidy` operations for improved scalability in large certificate stores. [[GH-678](https://github.com/openbao/openbao/pull/678)]
* secrets/kv: add a `detailed-metadata/:prefix` endpoint that supports listing entries along with their corresponding metadata in the detailed key_info response field [[GH-766](https://github.com/openbao/openbao/pull/766)]
* transit: Use transactions for read + write policy operations [[GH-956](https://github.com/openbao/openbao/pull/956)]
* ui: Remove client count menu [[GH-734](https://github.com/openbao/openbao/pull/734)]

BUG FIXES:

* core-listener: Fix operator diagnose with unix-socker listener [[GH-958](https://github.com/openbao/openbao/pull/958)]
* raft: Fix noisy warn on follower-less keyring rotation. [[GH-937](https://github.com/openbao/openbao/pull/937)]
* secrets/pki: Fix bao pki health-check detection on non-pki mounts. [[GH-935](https://github.com/openbao/openbao/pull/935)]
* ui: fix missing checkmarks in all checkboxes, due to invalid use of sass-svg-uri package [[GH-1042](https://github.com/openbao/openbao/pull/1042)]

## 2.2.0-beta20250213
## February 13, 2025

CHANGES:

* command/server: Prevent and warn about loading of duplicate config file from config directory. [[GH-816](https://github.com/openbao/openbao/pull/816)]
* container: Set -dev-no-store-token in default container images, fixing default read-only containers. [[GH-826](https://github.com/openbao/openbao/pull/826)]
* core/seal: remove support for legacy pre-keyring barrier entries
core/seal: remove support for legacy (direct) shamir unseal keys [[GH-750](https://github.com/openbao/openbao/pull/750)]

FEATURES:

* **ACME TLS Listener Certificate Provisioning**: Automatically fetch TLS certificates for OpenBao Server's TCP listeners via an Automatic Certificate Management Environment (ACME - RFC 8555) capable certificate authority (CA). This allows OpenBao to be self-hosted, using a CA contained within the instance to sign the instance's own certificates. [[GH-857](https://github.com/openbao/openbao/pull/857)]
* **PKCS#11 Auto-Unseal**: Add support for automatic unsealing of OpenBao using a PKCS#11-enabled Hardware Security Module (HSM) or Key Management System (KMS). [[GH-889](https://github.com/openbao/openbao/pull/889)]
* **Scanning**: introduce the ability to recursively list (scan) within plugins, adding a separate `scan` ACL capability, operation type, HTTP verb (`SCAN` with `GET` fallback via `?scan=true`), API, and CLI support. This also adds support to the KVv1 and KVv2 engines. [[GH-763](https://github.com/openbao/openbao/pull/763)]
* **Transit**: Add support for key derivation mechanisms (derives a new key from a base key).
   - This path uses the named base key and derivation algorithm specific parameters to derive a new named key.
   - Currently, only the ECDH key agreement algorithm is supported: the base key is one's own ECC private key and the "peer_public_key" is the pem-encoded other party's ECC public key.The computed shared secret is the resulting derived key. [[GH-811](https://github.com/openbao/openbao/pull/811)]
* **UI**: Reintroduction of the WebUI. [[GH-940](https://github.com/openbao/openbao/pull/940)]
* raft: Added support for nodes to join the Raft cluster as non-voters. [[GH-741](https://github.com/openbao/openbao/pull/741)]

IMPROVEMENTS:

* audit: modify the hashWalker to handle nested structs without panicking [[GH-887](https://github.com/openbao/openbao/pull/887)]
* auth: Use transactions for read-then-write methods in the credential package [[GH-952](https://github.com/openbao/openbao/pull/952)]
* auth: Use transactions for write and delete config for various auth methods. [[GH-878](https://github.com/openbao/openbao/pull/878)]
* core/mounts: Allow tuning HMAC request and response parameters on sys/, cubbyhole/, and identity/, enabling auditing of core policy changes. [[GH-921](https://github.com/openbao/openbao/pull/921)]
* core/policies: Allow listing policies under a given prefix. [[GH-736](https://github.com/openbao/openbao/pull/736)]
* core/policies: add `pagination_limit` to ACL policies for enforcing max pagination sizes. [[GH-802](https://github.com/openbao/openbao/pull/802)]
* core: Bump to latest Go toolchain 1.24.0. [[GH-1000](https://github.com/openbao/openbao/pull/1000)]
* rabbitmq: Use transactions for read-then-write methods in the rabbitmq package [[GH-997](https://github.com/openbao/openbao/pull/997)]
* secret/pki: Add new endpoint `pki/certs/detailed` to return detailed cert list. [[GH-680](https://github.com/openbao/openbao/pull/680)]
* secret/pki: Add pagination to `tidy` operations for improved scalability in large certificate stores. [[GH-678](https://github.com/openbao/openbao/pull/678)]
* secrets/kv: add a `detailed-metadata/:prefix` endpoint that supports listing entries along with their corresponding metadata in the detailed key_info response field [[GH-766](https://github.com/openbao/openbao/pull/766)]
* transit: Use transactions for read + write policy operations [[GH-956](https://github.com/openbao/openbao/pull/956)]
* ui: Remove client count menu [[GH-734](https://github.com/openbao/openbao/pull/734)]

BUG FIXES:

* core-listener: Fix operator diagnose with unix-socker listener [[GH-958](https://github.com/openbao/openbao/pull/958)]
* raft: Fix noisy warn on follower-less keyring rotation. [[GH-937](https://github.com/openbao/openbao/pull/937)]
* secrets/pki: Fix bao pki health-check detection on non-pki mounts. [[GH-935](https://github.com/openbao/openbao/pull/935)]

## 2.1.1
## January 21, 2025

IMPROVEMENTS:

* core: Bump to latest Go toolchain 1.23.5. [[GH-912](https://github.com/openbao/openbao/pull/912)]

## 2.1.0
## November 29, 2024

SECURITY:

* core/identity: fix root namespace privilege escalation via entity modification. HCSEC-2024-21 / CVE-2024-9180. [[GH-695](https://github.com/openbao/openbao/pull/695)]
* raft: Fix memory exhaustion when processing raft cluster join requests; results in longer challenge/answers. HCSEC-2024-26 / CVE-2024-8185. [[GH-690](https://github.com/openbao/openbao/pull/690)]
* secrets/ssh: Deny globally valid certificate issuance without valid_principals or allow_empty_principals override. HCSEC-2024-20 / CVE-2024-7594. (**potentially breaking**) [[GH-561](https://github.com/openbao/openbao/pull/561)]

CHANGES:

* api: Load all CA certificates specified in environment variables. [[GH-574](https://github.com/openbao/openbao/pull/574)]
* auth/userpass: Drop support for Vault v0.2 password entries with no hash.
sys/initialize: Drop support for pre Vault 1.3 stored Shamir share unseal.
command/ssh: Drop support for pre Vault 1.1 auto-SSH role detection.
plugins: Drop support for pre Vault 0.9.4 non-GRPC communication protocols.
core: Drop support for pre Vault 1.10 batch tokens.
core: Drop support for pre Vault 1.0 namespaces. [[GH-457](https://github.com/openbao/openbao/pull/457)]
* cli: Remove 'bao transform ...' CLIs as the Transform plugin is not present in OpenBao. [[GH-455](https://github.com/openbao/openbao/pull/455)]
* command/debug: Replace mholt/archiver with standard library utils. This may change file permissions but does not affect archive layout. [[GH-611](https://github.com/openbao/openbao/pull/611)]
* serviceregistration/kubernetes: labels use `openbao` as prefix instead of `vault`. [[GH-416](https://github.com/openbao/openbao/pull/416)]
* core: Remove support for Solaris due to lack of Docker support. [[GH-710](https://github.com/openbao/openbao/pull/710)]

FEATURES:

* **Remove Mount Table Limits**: Using transactional storage, we've split the
auth and secret mount tables into separate storage entries, removing the
requirement that the entire table fit into a single storage entry limited by
`max_entry_size`. This allows potentially hundreds of thousands of mounts on
a single scaled-up server. [[GH-622](https://github.com/openbao/openbao/pull/622)]
* **Transactional Storage**: Plugin developers can now take advantage of safe
  storage modification APIs when the underlying physical storage supports
  them. The `physical.TransactionalBackend` and `logical.TransactionalStorage`
  types allow developers to begin read-only and writable transactions,
  committing or rolling back the desired changes. [[GH-292](https://github.com/openbao/openbao/pull/292)]
* **Transit**: Support PKI CSR and certificate storage alongside key material. This allows callers to securely create keys and submit requests for certificates without the key material leaving Transit. Storage of the certificate on the key avoids the need for an additional K/V mount. Rotation of this certificate and its chain is also supported. [[GH-536](https://github.com/openbao/openbao/pull/536)]
* auth/oidc: Add a new `callback_mode` role option value `device` to use the oidc device flow instead of a callback, add a new `poll_interval` role option to control how often to poll for a response, and add a new `callbackmode=device` option to the oidc login method in the cli. [[GH-319](https://github.com/openbao/openbao/pull/319)]
* auth/oidc: Add new `callback_mode=direct` role option to cause the oidc callback to be direct to the server instead of the client, and add a `callbackmode=direct` option to the oidc login method in the cli. [[GH-318](https://github.com/openbao/openbao/pull/318)]
* physical/postgres: Reintroduce Postgres database for OpenBao storage, implementing paginated list support. This feature is currently in **preview** and breaking changes may occur. [[GH-467](https://github.com/openbao/openbao/pull/467)]

IMPROVEMENTS:

* auth/jwt: Allow templating ACL policies from data in claims on JWT or OIDC ID tokens. [[GH-618](https://github.com/openbao/openbao/pull/618)]
* auth/oidc: Add a new `oauth2_metadata` configuration option to enable sending any of the tokens from the token issuer to the client. [[GH-320](https://github.com/openbao/openbao/pull/320)]
* core: Add endpoint to inspect request information [[GH-513](https://github.com/openbao/openbao/pull/513)]
* core: Update to Go 1.23.3. [[GH-699](https://github.com/openbao/openbao/pull/699)]
* core: Upgrade RHEL UBI container image to 9.5. [[GH-701](https://github.com/openbao/openbao/pull/701)]
* docker: add `/bin/vault` symlink to docker images [[GH-548](https://github.com/openbao/openbao/pull/548)]
* raft: Update to hashicorp/raft@v1.7.1, go.etcd.io/bbolt@v1.3.11 for bug fixes and performance improvements. [[GH-633](https://github.com/openbao/openbao/pull/633)]
* rpm: Fix packaging to properly annotate configs entries for noreplace [[GH-639](https://github.com/openbao/openbao/pull/639)]
* sdk: Use quay.io/openbao/openbao in containerized testing [[GH-427](https://github.com/openbao/openbao/pull/427)]
* secret/pki: Add `revoked_safety_buffer` to control retention on revoked certificates separately from expired certificates. [[GH-653](https://github.com/openbao/openbao/pull/653)]
* secret/pki: Delete invalid certificates during tidy via `tidy_invalid_certs=true` if they cannot be parsed due to Go's x509 handling. [[GH-665](https://github.com/openbao/openbao/pull/665)]
* secret/pki: Support revoking expired certificates with the `allow_expired_cert_revocation` CRL configuration. [[GH-638](https://github.com/openbao/openbao/pull/638)]
* secrets/kv: Implement transactions to prevent canceled operations from corrupting storage. [[GH-560](https://github.com/openbao/openbao/pull/560)]
* secrets/pki: Use transactions for root generation, issuer import [[GH-498](https://github.com/openbao/openbao/pull/498)]
* secrets/pki: add `not_before` parameter to precisely define a certificate's "not before" field. [[GH-515](https://github.com/openbao/openbao/pull/515)]
* storage/postgresql: Add support for transactional storage semantics. [[GH-608](https://github.com/openbao/openbao/pull/608)]
* storage/postgresql: Allow table creation to improve first-start UX. [[GH-614](https://github.com/openbao/openbao/pull/614)]
* storage/raft: Add support for transactional storage semantics. [[GH-292](https://github.com/openbao/openbao/pull/292)]
* ui: Remove Vault references on sibebar, splash screen & loading page. [[GH-668](https://github.com/openbao/openbao/pull/668)]
* ui: Update documentation links. [[GH-669](https://github.com/openbao/openbao/pull/669)]

BUG FIXES:

* api/output_string: Change vault reference to bao. [[GH-511](https://github.com/openbao/openbao/pull/511)]
* cli: Always pass `BAO_ADDR` to the token helper, so the token helper can know
the address even if it was provided through the `-address` flag. For
compatibility we also set `VAULT_ADDR`. [[GH-348](https://github.com/openbao/openbao/pull/348)]
* core: Fix server panic on AppRole login requests with invalid parameter typing [[GH-512](https://github.com/openbao/openbao/pull/512)]
* docker: fix collision between the cluster address and local JSON configuration sharing the same variable within the docker-entrypoint script [[GH-446](https://github.com/openbao/openbao/pull/446)]
* docker: fix configuration of bao cluster and redirect address on separate interfaces when using environment variables [[GH-682](https://github.com/openbao/openbao/pull/682)]
* physical/cache: Ensure later modifications to entry do not impact cached value. [[GH-483](https://github.com/openbao/openbao/pull/483)]
* release: remove changelog/ directory from binary release tarballs [[GH-641](https://github.com/openbao/openbao/pull/641)]
* secrets/pki: Fix ACME HTTP-01 challenge validation with IPv6 addresses [[GH-559](https://github.com/openbao/openbao/pull/559)]
* secrets/pki: Fix handling of reusing existing Ed25519 keys [[GH-461](https://github.com/openbao/openbao/pull/461)]
* serviceregistration/k8s: Fix compatibility with legacy VAULT_-prefixed environment variables. [[GH-527](https://github.com/openbao/openbao/pull/527)]

## 2.1.0-beta20241114
## November 14, 2024

SECURITY:

* core/identity: fix root namespace privilege escalation via entity modification. HCSEC-2024-21 / CVE-2024-9180. [[GH-695](https://github.com/openbao/openbao/pull/695)]
* raft: Fix memory exhaustion when processing raft cluster join requests; results in longer challenge/answers. HCSEC-2024-26 / CVE-2024-8185. [[GH-690](https://github.com/openbao/openbao/pull/690)]
* secrets/ssh: Deny globally valid certificate issuance without valid_principals or allow_empty_principals override. HCSEC-2024-20 / CVE-2024-7594. (**potentially breaking**) [[GH-561](https://github.com/openbao/openbao/pull/561)]

CHANGES:

* api: Load all CA certificates specified in environment variables. [[GH-574](https://github.com/openbao/openbao/pull/574)]
* auth/userpass: Drop support for Vault v0.2 password entries with no hash.
sys/initialize: Drop support for pre Vault 1.3 stored Shamir share unseal.
command/ssh: Drop support for pre Vault 1.1 auto-SSH role detection.
plugins: Drop support for pre Vault 0.9.4 non-GRPC communication protocols.
core: Drop support for pre Vault 1.10 batch tokens.
core: Drop support for pre Vault 1.0 namespaces. [[GH-457](https://github.com/openbao/openbao/pull/457)]
* cli: Remove 'bao transform ...' CLIs as the Transform plugin is not present in OpenBao. [[GH-455](https://github.com/openbao/openbao/pull/455)]
* command/debug: Replace mholt/archiver with standard library utils. This may change file permissions but does not affect archive layout. [[GH-611](https://github.com/openbao/openbao/pull/611)]
* serviceregistration/kubernetes: labels use `openbao` as prefix instead of `vault`. [[GH-416](https://github.com/openbao/openbao/pull/416)]
* core: Remove support for Solaris due to lack of Docker support. [[GH-710](https://github.com/openbao/openbao/pull/710)]

FEATURES:

* **Remove Mount Table Limits**: Using transactional storage, we've split the
auth and secret mount tables into separate storage entries, removing the
requirement that the entire table fit into a single storage entry limited by
`max_entry_size`. This allows potentially hundreds of thousands of mounts on
a single scaled-up server. [[GH-622](https://github.com/openbao/openbao/pull/622)]
* **Transactional Storage**: Plugin developers can now take advantage of safe
  storage modification APIs when the underlying physical storage supports
  them. The `physical.TransactionalBackend` and `logical.TransactionalStorage`
  types allow developers to begin read-only and writable transactions,
  committing or rolling back the desired changes. [[GH-292](https://github.com/openbao/openbao/pull/292)]
* **Transit**: Support PKI CSR and certificate storage alongside key material. This allows callers to securely create keys and submit requests for certificates without the key material leaving Transit. Storage of the certificate on the key avoids the need for an additional K/V mount. Rotation of this certificate and its chain is also supported. [[GH-536](https://github.com/openbao/openbao/pull/536)]
* auth/oidc: Add a new `callback_mode` role option value `device` to use the oidc device flow instead of a callback, add a new `poll_interval` role option to control how often to poll for a response, and add a new `callbackmode=device` option to the oidc login method in the cli. [[GH-319](https://github.com/openbao/openbao/pull/319)]
* auth/oidc: Add new `callback_mode=direct` role option to cause the oidc callback to be direct to the server instead of the client, and add a `callbackmode=direct` option to the oidc login method in the cli. [[GH-318](https://github.com/openbao/openbao/pull/318)]
* physical/postgres: Reintroduce Postgres database for OpenBao storage, implementing paginated list support. This feature is currently in **preview** and breaking changes may occur. [[GH-467](https://github.com/openbao/openbao/pull/467)]

IMPROVEMENTS:

* auth/jwt: Allow templating ACL policies from data in claims on JWT or OIDC ID tokens. [[GH-618](https://github.com/openbao/openbao/pull/618)]
* auth/oidc: Add a new `oauth2_metadata` configuration option to enable sending any of the tokens from the token issuer to the client. [[GH-320](https://github.com/openbao/openbao/pull/320)]
* core: Add endpoint to inspect request information [[GH-513](https://github.com/openbao/openbao/pull/513)]
* core: Update to Go 1.23.3. [[GH-699](https://github.com/openbao/openbao/pull/699)]
* core: Upgrade RHEL UBI container image to 9.5. [[GH-701](https://github.com/openbao/openbao/pull/701)]
* docker: add `/bin/vault` symlink to docker images [[GH-548](https://github.com/openbao/openbao/pull/548)]
* raft: Update to hashicorp/raft@v1.7.1, go.etcd.io/bbolt@v1.3.11 for bug fixes and performance improvements. [[GH-633](https://github.com/openbao/openbao/pull/633)]
* rpm: Fix packaging to properly annotate configs entries for noreplace [[GH-639](https://github.com/openbao/openbao/pull/639)]
* sdk: Use quay.io/openbao/openbao in containerized testing [[GH-427](https://github.com/openbao/openbao/pull/427)]
* secret/pki: Add `revoked_safety_buffer` to control retention on revoked certificates separately from expired certificates. [[GH-653](https://github.com/openbao/openbao/pull/653)]
* secret/pki: Delete invalid certificates during tidy via `tidy_invalid_certs=true` if they cannot be parsed due to Go's x509 handling. [[GH-665](https://github.com/openbao/openbao/pull/665)]
* secret/pki: Support revoking expired certificates with the `allow_expired_cert_revocation` CRL configuration. [[GH-638](https://github.com/openbao/openbao/pull/638)]
* secrets/kv: Implement transactions to prevent canceled operations from corrupting storage. [[GH-560](https://github.com/openbao/openbao/pull/560)]
* secrets/pki: Use transactions for root generation, issuer import [[GH-498](https://github.com/openbao/openbao/pull/498)]
* secrets/pki: add `not_before` parameter to precisely define a certificate's "not before" field. [[GH-515](https://github.com/openbao/openbao/pull/515)]
* storage/postgresql: Add support for transactional storage semantics. [[GH-608](https://github.com/openbao/openbao/pull/608)]
* storage/postgresql: Allow table creation to improve first-start UX. [[GH-614](https://github.com/openbao/openbao/pull/614)]
* storage/raft: Add support for transactional storage semantics. [[GH-292](https://github.com/openbao/openbao/pull/292)]
* ui: Remove Vault references on sibebar, splash screen & loading page. [[GH-668](https://github.com/openbao/openbao/pull/668)]
* ui: Update documentation links. [[GH-669](https://github.com/openbao/openbao/pull/669)]

BUG FIXES:

* api/output_string: Change vault reference to bao. [[GH-511](https://github.com/openbao/openbao/pull/511)]
* cli: Always pass `BAO_ADDR` to the token helper, so the token helper can know
the address even if it was provided through the `-address` flag. For
compatibility we also set `VAULT_ADDR`. [[GH-348](https://github.com/openbao/openbao/pull/348)]
* core: Fix server panic on AppRole login requests with invalid parameter typing [[GH-512](https://github.com/openbao/openbao/pull/512)]
* docker: fix collision between the cluster address and local JSON configuration sharing the same variable within the docker-entrypoint script [[GH-446](https://github.com/openbao/openbao/pull/446)]
* docker: fix configuration of bao cluster and redirect address on separate interfaces when using environment variables [[GH-682](https://github.com/openbao/openbao/pull/682)]
* physical/cache: Ensure later modifications to entry do not impact cached value. [[GH-483](https://github.com/openbao/openbao/pull/483)]
* release: remove changelog/ directory from binary release tarballs [[GH-641](https://github.com/openbao/openbao/pull/641)]
* secrets/pki: Fix ACME HTTP-01 challenge validation with IPv6 addresses [[GH-559](https://github.com/openbao/openbao/pull/559)]
* secrets/pki: Fix handling of reusing existing Ed25519 keys [[GH-461](https://github.com/openbao/openbao/pull/461)]
* serviceregistration/k8s: Fix compatibility with legacy VAULT_-prefixed environment variables. [[GH-527](https://github.com/openbao/openbao/pull/527)]

## 2.0.3
## November 15, 2024

SECURITY:

* core/identity: fix root namespace privilege escalation via entity modification. HCSEC-2024-21 / CVE-2024-9180. [[GH-695](https://github.com/openbao/openbao/pull/695)]
* raft: Fix memory exhaustion when processing raft cluster join requests; results in longer challenge/answers. HCSEC-2024-26 / CVE-2024-8185. [[GH-690](https://github.com/openbao/openbao/pull/690)]

CHANGES:

* command/debug: Replace mholt/archiver with standard library utils. This may change file permissions but does not affect archive layout. [[GH-611](https://github.com/openbao/openbao/pull/611)]

IMPROVEMENTS:

* core: Update to Go 1.22.9. [[GH-725](https://github.com/openbao/openbao/pull/725)]
* core: Upgrade RHEL UBI container image to 9.5. [[GH-701](https://github.com/openbao/openbao/pull/701)]

BUG FIXES:

* release: remove changelog/ directory from binary release tarballs [[GH-641](https://github.com/openbao/openbao/pull/641)]

## 2.0.2
## October 5, 2024

SECURITY:

* secrets/ssh: Deny globally valid certificate issuance without valid_principals or allow_empty_principals override. HCSEC-2024-20 / CVE-2024-7594. (**potentially breaking**) [[GH-561](https://github.com/openbao/openbao/pull/561)]

IMPROVEMENTS:

* docker: add `/bin/vault` symlink to docker images [[GH-548](https://github.com/openbao/openbao/pull/548)]

BUG FIXES:

* api/output_string: Change vault reference to bao. [[GH-511](https://github.com/openbao/openbao/pull/511)]
* core: Fix server panic on AppRole login requests with invalid parameter typing [[GH-512](https://github.com/openbao/openbao/pull/512)]
* secrets/pki: Fix ACME HTTP-01 challenge validation with IPv6 addresses [[GH-559](https://github.com/openbao/openbao/pull/559)]
* serviceregistration/k8s: Fix compatibility with legacy VAULT_-prefixed environment variables. [[GH-527](https://github.com/openbao/openbao/pull/527)]

## 2.0.1
## September 3, 2024

CHANGES:

* serviceregistration/kubernetes: labels use `openbao` as prefix instead of `vault`. [[GH-416](https://github.com/openbao/openbao/pull/416)]

IMPROVEMENTS:

* core: Update Go to 1.22.6 [[GH-504](https://github.com/openbao/openbao/pull/504)]

BUG FIXES:

* cli: Always pass `BAO_ADDR` to the token helper, so the token helper can know
the address even if it was provided through the `-address` flag. For
compatibility we also set `VAULT_ADDR`. [[GH-348](https://github.com/openbao/openbao/pull/348)]
* docker: fix collision between the cluster address and local JSON configuration sharing the same variable within the docker-entrypoint script [[GH-446](https://github.com/openbao/openbao/pull/446)]
* secrets/pki: Fix handling of reusing existing Ed25519 keys [[GH-461](https://github.com/openbao/openbao/pull/461)]

## 2.0.0
### July 16, 2024

> [!WARNING]
> OpenBao's 2.0.0 GA does not include the builtin WebUI! You can only access a running Bao instance via the CLI or API.

SECURITY:

* auth/cert: compare full bytes of trusted leaf certificates with incoming client certificates to prevent trusting certs with the same serial number but not the same public/private key. [[GH-173](https://github.com/openbao/openbao/pull/173)]
* auth/jwt: BREAKING: Fix handling of aud claims which are a single string, to behave the same as list claims. [[GH-263](https://github.com/openbao/openbao/pull/263)]

CHANGES:

* added other registries for docker images [[GH-269](https://github.com/openbao/openbao/pull/269)]
* core: Bump Go version to 1.22.0. [[GH-120](https://github.com/openbao/openbao/pull/120)]
* core: OpenBao version 2.0.0-alpha20240329.

  core: Retracted all prior Vault versions.

  api: Retracted all prior Vault versions.

  sdk: Retracted all prior Vault versions. [[GH-238](https://github.com/openbao/openbao/pull/238)]

* core: Remove mlock functionality from OpenBao and make the "disable_mlock" config option obsolete. [[GH-363](https://github.com/openbao/openbao/pull/363)]
* secret/transit: Remove ability to use v1 and v2 Transit convergent encryption keys migrated from Vault v0.6.2 or earlier. [[GH-85](https://github.com/openbao/openbao/pull/85)]

FEATURES:

* **Paginated Lists**: Allow plugins to support pagination on `LIST` requests, reducing server and client burden by limiting large responses. This uses optional `after` and `limit` parameters for clients to control the size of responses with a relative indexing into result entry sets. [[GH-170](https://github.com/openbao/openbao/pull/170)]

IMPROVEMENTS:

* auth: Add token_strictly_bind_ip to support strictly binding issued token to login request's IP address. [[GH-202](https://github.com/openbao/openbao/pull/202)]
* cli: Expand handling of -non-interactive to prevent reading from stdin. [[GH-221](https://github.com/openbao/openbao/pull/221)]
* sdk/helper/shamir: Use CS-PRNG for shuffling X coordinates; do not rely on math/rand. [[GH-210](https://github.com/openbao/openbao/pull/210)]
* sdk/helper/shamir: move Shamir's code into public SDK namespace to encourage external reuse [[GH-181](https://github.com/openbao/openbao/pull/181)]
* secret/pki: Add Delta CRL Distribution Point to AIA URLs, allowing AIA-aware clients to find Delta CRLs dynamically. [[GH-215](https://github.com/openbao/openbao/pull/215)]
* secret/pki: Add support for KeyUsage, ExtKeyUsage when issuing CA certificates, allowing compliance with CA/BF guidelines (e.g., with GCP Load Balancers). [[GH-76](https://github.com/openbao/openbao/pull/76)]
* secret/pki: Add support for basicConstraints x509 extension when issuing certificates with sign-verbatim. [[GH-201](https://github.com/openbao/openbao/pull/201)]
* secret/pki: Allow pki/issue/:role with key_type=any roles, via explicit key_type and key_bits request parameters. [[GH-209](https://github.com/openbao/openbao/pull/209)]
* secret/transit: Add support for XChaCha20-Poly1305 keys, preventing nonce-reuse without key rotation. [[GH-36](https://github.com/openbao/openbao/pull/36)]
* secret/transit: Allow choosing export key format, specifying format=der or format=pem for consistent PKIX encoded public keys. [[GH-212](https://github.com/openbao/openbao/pull/212)]
* secret/transit: Allow soft deletion of keys, preventing their use and rotation but retaining key material until restored or fully deleted. [[GH-211](https://github.com/openbao/openbao/pull/211)]
* secrets/pki: Remove Vault Enterprise-only cross-cluster, unified CRL stubs (breaking). [[GH-365](https://github.com/openbao/openbao/pull/365)]
* ui: The latest versions of Chrome do not automatically redirect back to an Android app after multiple redirects during an OIDC authentication flow. A link was added to allow the user to manually redirect back to the app. [[GH-184](https://github.com/openbao/openbao/pull/184)]

BUG FIXES:

* cli/login: Avoid calling the token helper in `get` mode. [[GH-313](https://github.com/openbao/openbao/pull/313)]
* core/pluings: Fix compatibility when running pre-built Vault plugins. [[GH-321](https://github.com/openbao/openbao/pull/321)]
* core: re-introduce Server Side Consistent Tokens (SSCTs) from upstream, defaulting to disabled [[GH-298](https://github.com/openbao/openbao/pull/298)]
* packaging: fix systemd service to refer to /etc/openbao/env for environment variables [[GH-275](https://github.com/openbao/openbao/pull/275)]
* physical/raft: fix ListPage calls when after=. resulting in an empty list [[GH-294](https://github.com/openbao/openbao/pull/294)]
* secret/pki: Use user-submitted ordering for SANs, fixing issues where automatic ordering causes parse failures in some browsers. [[GH-50](https://github.com/openbao/openbao/pull/50)]
* secret/rabbitmq: Fix role reading causing audit log panic when vhost_topics are set. [[GH-224](https://github.com/openbao/openbao/pull/224)]
* secret/transit: Allow use of generated destination wrapping keys rather than strictly requiring exported keys. [[GH-211](https://github.com/openbao/openbao/pull/211)]

## 2.0.0-beta20240618
### June 18, 2024

> [!WARNING]
> OpenBao's Beta Release does not include the builtin WebUI! You can only access a running Bao instance via the CLI or API.

CHANGES:

* added other registries for docker images [[GH-269](https://github.com/openbao/openbao/pull/269)]

BUG FIXES:

* cli/login: Avoid calling the token helper in `get` mode. [[GH-313](https://github.com/openbao/openbao/pull/313)]
* core/pluings: Fix compatibility when running pre-built Vault plugins. [[GH-321](https://github.com/openbao/openbao/pull/321)]
* core: re-introduce Server Side Consistent Tokens (SSCTs) from upstream, defaulting to disabled [[GH-298](https://github.com/openbao/openbao/pull/298)]
* packaging: fix systemd service to refer to /etc/openbao/env for environment variables [[GH-275](https://github.com/openbao/openbao/pull/275)]
* physical/raft: fix ListPage calls when after=. resulting in an empty list [[GH-294](https://github.com/openbao/openbao/pull/294)]

## 2.0.0-alpha20240329
### March 29, 2024

> [!WARNING]
> OpenBao's Alpha Release does not include the builtin WebUI! You can only access a running Bao instance via the CLI or API.

SECURITY:

* auth/cert: compare full bytes of trusted leaf certificates with incoming client certificates to prevent trusting certs with the same serial number but not the same public/private key. [[GH-173](https://github.com/openbao/openbao/pull/173)]

CHANGES:

* core: Bump Go version to 1.22.0. [[GH-120](https://github.com/openbao/openbao/pull/120)]
* core: OpenBao version 2.0.0-alpha20240329.
core: Retracted all prior Vault versions.
api: Retracted all prior Vault versions.
sdk: Retracted all prior Vault versions. [[GH-238](https://github.com/openbao/openbao/pull/238)]
* secret/transit: Remove ability to use v1 and v2 Transit convergent encryption keys migrated from Vault v0.6.2 or earlier. [[GH-85](https://github.com/openbao/openbao/pull/85)]

FEATURES:

* **Paginated Lists**: Allow plugins to support pagination on `LIST` requests, reducing server and client burden by limiting large responses. This uses optional `after` and `limit` parameters for clients to control the size of responses with a relative indexing into result entry sets. [[GH-170](https://github.com/openbao/openbao/pull/170)]

IMPROVEMENTS:

* auth: Add token_strictly_bind_ip to support strictly binding issued token to login request's IP address. [[GH-202](https://github.com/openbao/openbao/pull/202)]
* cli: Expand handling of -non-interactive to prevent reading from stdin. [[GH-221](https://github.com/openbao/openbao/pull/221)]
* sdk/helper/shamir: Use CS-PRNG for shuffling X coordinates; do not rely on math/rand. [[GH-210](https://github.com/openbao/openbao/pull/210)]
* sdk/helper/shamir: move Shamir's code into public SDK namespace to encourage external reuse [[GH-181](https://github.com/openbao/openbao/pull/181)]
* secret/pki: Add Delta CRL Distribution Point to AIA URLs, allowing AIA-aware clients to find Delta CRLs dynamically. [[GH-215](https://github.com/openbao/openbao/pull/215)]
* secret/pki: Add support for KeyUsage, ExtKeyUsage when issuing CA certificates, allowing compliance with CA/BF guidelines (e.g., with GCP Load Balancers). [[GH-76](https://github.com/openbao/openbao/pull/76)]
* secret/pki: Add support for basicConstraints x509 extension when issuing certificates with sign-verbatim. [[GH-201](https://github.com/openbao/openbao/pull/201)]
* secret/pki: Allow pki/issue/:role with key_type=any roles, via explicit key_type and key_bits request parameters. [[GH-209](https://github.com/openbao/openbao/pull/209)]
* secret/transit: Add support for XChaCha20-Poly1305 keys, preventing nonce-reuse without key rotation. [[GH-36](https://github.com/openbao/openbao/pull/36)]
* secret/transit: Allow choosing export key format, specifying format=der or format=pem for consistent PKIX encoded public keys. [[GH-212](https://github.com/openbao/openbao/pull/212)]
* secret/transit: Allow soft deletion of keys, preventing their use and rotation but retaining key material until restored or fully deleted. [[GH-211](https://github.com/openbao/openbao/pull/211)]
* ui: The latest versions of Chrome do not automatically redirect back to an Android app after multiple redirects during an OIDC authentication flow. A link was added to allow the user to manually redirect back to the app. [[GH-184](https://github.com/openbao/openbao/pull/184)]

BUG FIXES:

* secret/pki: Use user-submitted ordering for SANs, fixing issues where automatic ordering causes parse failures in some browsers. [[GH-50](https://github.com/openbao/openbao/pull/50)]
* secret/rabbitmq: Fix role reading causing audit log panic when vhost_topics are set. [[GH-224](https://github.com/openbao/openbao/pull/224)]
* secret/transit: Allow use of generated destination wrapping keys rather than strictly requiring exported keys. [[GH-211](https://github.com/openbao/openbao/pull/211)]
