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
* **Transit**: Add support for key derivation mechansims (derives a new key from a base key).
   - This path uses the named base key and derivation algorithm specific parameters to derive a new named key.
   - Currently, only the ECDH key agreement algorithm is supported: the base key is one's own ECC private key and the "peer_public_key" is the pem-encoded other party's ECC public key.The computed shared secret is the resulting derived key. [[GH-811](https://github.com/openbao/openbao/pull/811)]
* **UI**: Reintroduction of the WebUI. [[GH-940](https://github.com/openbao/openbao/pull/940)]
* raft: Added support for nodes to join the Raft cluster as non-voters. [[GH-741](https://github.com/openbao/openbao/pull/741)]

IMPROVEMENTS:

* audit: modify the hashWalker to handle nested structs without panicing [[GH-887](https://github.com/openbao/openbao/pull/887)]
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
* **Transit**: Add support for key derivation mechansims (derives a new key from a base key).
   - This path uses the named base key and derivation algorithm specific parameters to derive a new named key.
   - Currently, only the ECDH key agreement algorithm is supported: the base key is one's own ECC private key and the "peer_public_key" is the pem-encoded other party's ECC public key.The computed shared secret is the resulting derived key. [[GH-811](https://github.com/openbao/openbao/pull/811)]
* **UI**: Reintroduction of the WebUI. [[GH-940](https://github.com/openbao/openbao/pull/940)]
* raft: Added support for nodes to join the Raft cluster as non-voters. [[GH-741](https://github.com/openbao/openbao/pull/741)]

IMPROVEMENTS:

* audit: modify the hashWalker to handle nested structs without panicing [[GH-887](https://github.com/openbao/openbao/pull/887)]
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
auth and secret mount tables into separate storage entires, removing the
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
auth and secret mount tables into separate storage entires, removing the
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
