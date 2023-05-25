## Unreleased

## 0.16.0 (May 25, 2023)
* Add display attributes for OpenAPI OperationID's [GH-192](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/192)
* update dependencies [GH-196](https://github.com/hashicorp/vault-plugin-secrets-kubernetes/pull/196)
  * github.com/hashicorp/cap v0.3.0
  * github.com/hashicorp/vault/api v1.9.1
  * k8s.io/api v0.27.2
  * k8s.io/apimachinery v0.27.2

## 0.15.1 (March 27, 2023)

### Changes

* enable plugin multiplexing [GH-186](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/186)
* update dependencies
   * `github.com/hashicorp/vault/api` v1.9.0
   * `github.com/hashicorp/vault/sdk` v0.8.1
   * `github.com/go-test/deep` v1.0.8 -> v1.1.0
   * `github.com/hashicorp/go-hclog` v1.3.1 -> v1.5.0
   * `k8s.io/api` v0.25.3 -> v0.26.3
   * `k8s.io/apimachinery` v0.25.3 -> v0.26.3

## 0.15.0 (February 9, 2023)

### Changes

* Return HTTP 403 error code instead of 500 when JWT validation fails due to invalid issuer, audiences, or signing algorithm [GH-179](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/179)
* Checks the Kubernetes API is audience-aware by checking for at least one compatible audience in the response from TokenReviews [GH-179](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/179)
* Update to Go 1.19 [GH-166](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/166)
* Update dependencies [GH-166](https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/166):
|             MODULE              |              VERSION               | NEW VERSION | DIRECT | VALID TIMESTAMPS |
|---------------------------------|------------------------------------|-------------|--------|------------------|
| github.com/hashicorp/go-hclog   | v1.1.0                             | v1.3.1      | true   | true             |
| github.com/hashicorp/go-uuid    | v1.0.2                             | v1.0.3      | true   | true             |
| github.com/hashicorp/go-version | v1.2.0                             | v1.6.0      | true   | true             |
| github.com/hashicorp/vault/api  | v1.5.0                             | v1.8.2      | true   | true             |
| github.com/hashicorp/vault/sdk  | v0.5.3                             | v0.6.1      | true   | true             |
| k8s.io/api                      | v0.0.0-20190409092523-d687e77c8ae9 | v0.25.3     | true   | true             |
| k8s.io/apimachinery             | v0.22.2                            | v0.25.3     | true   | true             |
