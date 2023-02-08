## Unreleased

## 0.15.0

IMPROVEMENTS:

* Adds `abort_on_error` parameter to CLI login command to help in non-interactive contexts [[GH-214]](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/214)
* Adds ability to set Google Workspace domain for groups search [[GH-220]](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/220)

## 0.14.0

* Updates dependency `google.golang.org/api@v0.83.0` [[GH-205](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/205)]
* Add Custom Provider for SecureAuth IdP [[GH-196](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/196)]
* Improves detection of Windows Subsystem for Linux (WSL) in CLI [[GH-209](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/209)]
* Adds support for Microsoft US Gov L4 to the Azure provider for groups fetching [[GH-211](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/211)]

## 0.13.0

* Adds ability to use JSON pointer syntax for the `user_claim` value [[GH-204](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/204)]

## 0.12.0

* Uses Proof Key for Code Exchange (PKCE) in OIDC flow [[GH-188](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/188)]

## 0.11.4

* Fixes OIDC auth from the Vault UI when using the implicit flow and `form_post` response mode [[GH-192](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/192)]

## 0.11.3

* Uses Proof Key for Code Exchange (PKCE) in OIDC flow [[GH-191](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/191)]

## 0.11.2

* Add a skip_browser argument to make auto-launching of the default browser optional [[GH-182](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/182)]

## 0.10.2

* Fixes OIDC auth from the Vault UI when using the implicit flow and `form_post` response mode [[GH-192](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/192)]

## 0.9.6

* Fixes OIDC auth from the Vault UI when using the implicit flow and `form_post` response mode [[GH-192](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/192)]

## 0.8.1

BUG FIXES:

* Fixes `bound_claims` validation for provider-specific group and user info fetching [[GH-149](https://github.com/hashicorp/vault-plugin-auth-jwt/pull/149)]
