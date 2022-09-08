## Unreleased

IMPROVEMENTS:

- Adds the `last_password` field to the static role [credential response](https://www.vaultproject.io/api-docs/secret/openldap#static-role-passwords)

BUG FIXES:

- Fix config updates so that they retain prior values set in storage
- Fix `last_bind_password` client rotation retry that may occur after a root credential rotation
