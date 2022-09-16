## Unreleased

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
