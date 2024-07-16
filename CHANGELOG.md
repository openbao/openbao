## 2.0.0
### July 16, 2024

> [!WARNING]
> OpenBao's 2.0.0 GA does not include the builtin WebUI! You can only access a running Bao instance via the CLI or API.

SECURITY:

* auth/cert: compare full bytes of trusted leaf certificates with incoming client certificates to prevent trusting certs with the same serial number but not the same public/private key. [[GH-173](https://github.com/openbao/openbao/pull/173)]

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
