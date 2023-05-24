## Unreleased

## v0.11.0

### IMPROVEMENTS:

* enable plugin multiplexing [GH-55](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/55)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1
  * `github.com/hashicorp/vault/sdk` v0.9.0

## v0.10.0

CHANGES:

* CreateOperation should only be implemented alongside ExistenceCheck [[GH-50]](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/50)

IMPROVEMENTS:

* Update golang.org/x/text to v0.3.8 [[GH-48]](https://github.com/hashicorp/vault-plugin-secrets-openldap/pull/48)

## v0.9.0

FEATURES:

- Adds service account check-out functionality for `ad`, `openldap`, and `racf` schemas.

IMPROVEMENTS:

- Adds the `last_password` field to the static role [credential response](https://www.vaultproject.io/api-docs/secret/openldap#static-role-passwords)
- Adds the `userdn` and `userattr` configuration parameters to control how user LDAP
  search is performed for service account check-out and static roles.
- Adds the `upndomain` configuration parameter to allow construction of a userPrincipalName
  (UPN) string for authentication.

BUG FIXES:

- Fix config updates so that they retain prior values set in storage
- Fix `last_bind_password` client rotation retry that may occur after a root credential rotation
