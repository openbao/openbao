## Unreleased

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
