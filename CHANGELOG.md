## Unreleased

## 0.5.0 (May 25, 2023)

### Features:

* allow omitting `kubernetes_namespace` on token create for single namespace Vault roles [GH-27](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/27)
* update dependencies [GH-196](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/30)
  * github.com/hashicorp/vault/api v1.9.1
  * github.com/stretchr/testify v1.8.3
  * k8s.io/api v0.27.2
  * k8s.io/apimachinery v0.27.2
  * k8s.io/client-go v0.27.2

## 0.4.0 (March 30, 2023)

### Features:

* add `audiences` option to set audiences for the k8s token created from the TokenRequest API, and add `token_default_audiences`
option to set the default audiences on role write [GH-24](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/24)

### Changes:

* enable plugin multiplexing [GH-23](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/23)
* update dependencies
   * `github.com/hashicorp/vault/api` v1.9.0
   * `github.com/hashicorp/vault/sdk` v0.8.1
   * `github.com/hashicorp/go-hclog` v1.3.1 -> v1.5.0
   * `github.com/stretchr/testify` v1.8.1 -> v1.8.2
   * `k8s.io/api` v0.25.3 -> v0.26.3
   * `k8s.io/apimachinery` v0.25.3 -> v0.26.3
   * `k8s.io/client-go` v0.25.3 -> v0.26.3

## 0.3.0 (February 9, 2023)

* Add `/check` endpoint to determine if environment variables are set [GH-18](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/18)

### Changes

* Update to Go 1.19 [GH-15](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/15)
* Update dependencies [GH-15](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/15):
|             MODULE              | VERSION | NEW VERSION | DIRECT | VALID TIMESTAMPS |
|---------------------------------|---------|-------------|--------|------------------|
| github.com/cenkalti/backoff/v3  | v3.0.0  | v3.2.2      | true   | true             |
| github.com/hashicorp/go-hclog   | v0.16.2 | v1.3.1      | true   | true             |
| github.com/hashicorp/go-version | v1.2.0  | v1.6.0      | true   | true             |
| github.com/hashicorp/vault/api  | v1.7.2  | v1.8.2      | true   | true             |
| github.com/hashicorp/vault/sdk  | v0.5.3  | v0.6.1      | true   | true             |
| github.com/stretchr/testify     | v1.8.0  | v1.8.1      | true   | true             |
| gopkg.in/square/go-jose.v2      | v2.5.1  | v2.6.0      | true   | true             |
| k8s.io/api                      | v0.22.2 | v0.25.3     | true   | true             |
| k8s.io/apimachinery             | v0.22.2 | v0.25.3     | true   | true             |
| k8s.io/client-go                | v0.22.2 | v0.25.3     | true   | true             |

## 0.2.0 (September 15, 2022)

### Changes

* Test against k8s versions 1.22-25, vault-helm 0.22.0, and Vault 1.11.3 [[GH-14](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/14)]
* Use go 1.19.1 [[GH-14](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/14)]

### Improvements

* Test against Vault Enterprise [[GH-11](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/11)]
* Role namespace configuration possible via LabelSelector [[GH-10](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/10)]
* Update golang dependencies to avoid CVEs [[GH-14](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/14)]
  * golang.org/x/crypto@v0.0.0-20220314234659-1baeb1ce4c0b
  * golang.org/x/net@v0.0.0-20220906165146-f3363e06e74c
  * golang.org/x/sys@v0.0.0-20220728004956-3c1f35247d10
  * github.com/stretchr/testify@v1.8.0

## 0.1.1 (May 26th, 2022)

### Changes

* Split `additional_metadata` into `extra_annotations` and `extra_labels` parameters [[GH-7](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/7)]

## 0.1.0 (May 20th, 2022)

Initial implementation [[GH-2](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/2)][[GH-3](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/3)][[GH-4](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/4)]
