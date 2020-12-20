# vault-plugin-database-redis

[![CircleCI](https://circleci.com/gh/hashicorp/vault-plugin-database-redis.svg?style=svg)](https://circleci.com/gh/hashicorp/vault-plugin-database-redis)

A [Vault](https://www.vaultproject.io) plugin for Redis

This project uses the database plugin interface introduced in Vault version 0.7.1.

The plugin supports the generation of static and dynamic user roles and root credential rotation.

## Build

To build this package for any platform you will need to clone this repository and cd into the repo directory and `go build -o redis-database-plugin ./cmd/redis-database-plugin/`. To test `go test` will execute a set of basic tests against against the docker.io/redis:latest redis database image. To test against different redis images, for example 5.0-buster, set the `REDIS_VERSION=5.0-buster` environment variable. If you want to run the tests against a local redis installation or an already running redis container, set the environment variable `REDIS_HOST` before executing. **Note** the tests assume that the redis database instance has a default user with the following ACL settings `user default on nopass ~* +@all`. If not you will need to align the Administrator username and password with the pre-set values in the `redis_test.go` file. Set VAULT_ACC to execute all of the tests. A subset of tests can be run using the command `go test -run TestDriver/Init` for example.

## Installation

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the
`vault-plugin-database-redis` executable generated above, into the directory.

**Please note:** This plugin is incompatible with Vault versions before 1.6.0 due to an update of the database plugin interface. You will be able to register the plugin in the plugins catalog with an older version of Vault but when you try to initialize the plugin to connect to a database instance you will get this error.
````bash
Error writing data to database/config/my-redis: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/config/my-redis
Code: 400. Errors:

* error creating database object: Incompatible API version with plugin. Plugin version: 5, Client versions: [3 4]
````

Sample commands for registering and starting to use the plugin:

```bash
$ SHA256=$(shasum -a 256 plugins/redis-database-plugin | cut -d' ' -f1)

$ vault secrets enable database

$ vault write sys/plugins/catalog/database/redis-database-plugin sha256=$SHA256 \
        command=redis-database-plugin
```

At this stage you are now ready to initialize the plugin to connect to the redis db using unencrypted or encrypted communications.

Prior to initializing the plugin, ensure that you have created an administration account. Vault will use the user specified here to create/update/revoke database credentials. That user must have the appropriate rule `+@admin` to perform actions upon other database users.

### Plugin initialization

```bash
$ vault write database/config/my-redis plugin_name="redis-database-plugin" \
        host="localhost" port=6379 username="Administrator" password="password" \
        allowed_roles="my-redis-*-role"

# You should consider rotating the admin password. Note that if you do, the new password will never be made available
# through Vault, so you should create a vault-specific database admin user for this.
$ vault write -force database/rotate-root/my-redis

 ```

### Dynamic Role Creation

When you create roles, you need to provide a JSON string containing the Redis ACL rules which are documented [here](https://redis.io/commands/acl-cat) or in the output of the `ACL CAT` redis command.

```bash
# if a creation_statement is not provided the user account will default to a read only user, '["~*", "+@read"]' that can read any key.
$ vault write database/roles/my-redis-admin-role db_name=my-redis \
        default_ttl="5m" max_ttl="1h" creation_statements='["+@admin"]'

$ vault write database/roles/my-redis-read-foo-role db_name=my-redis \
        default_ttl="5m" max_ttl="1h" creation_statements='["~foo", "+@read"]'
Success! Data written to: database/roles/my-redis-read-foo-role
```

To retrieve the credentials for the dynamic accounts

```bash

$vault read database/creds/my-redis-admin-role
Key                Value
---                -----
lease_id           database/creds/my-redis-admin-role/OxCTXJcxQ2F4lReWPjbezSnA
lease_duration     5m
lease_renewable    true
password           dACqHsav6-attdv1glGZ
username           V_TOKEN_MY-REDIS-ADMIN-ROLE_YASUQUF3GVVD0ZWTEMK4_1608481717

$ vault read database/creds/my-redis-read-foo-role
Key                Value
---                -----
lease_id           database/creds/my-redis-read-foo-role/Yn99BrX4t0NkLyifm4NmsEUB
lease_duration     5m
lease_renewable    true
password           ZN6gdTKszk7oc9Oztc-o
username           V_TOKEN_MY-REDIS-READ-FOO-ROLE_PUAINND1FC5XQGRC0HIF_1608481734

```

### Static Role Creation

In order to use static roles, the user must already exist in the Redis ACL list. The example below assumes that there is an existing user with the name "vault-edu". If the user does not exist you will receive the following error.

```bash
Error writing data to database/static-roles/static-account: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/static-roles/static-account
Code: 400. Errors:

* cannot update static account username

```

```bash
$ vault write database/static-roles/static-account db_name=insecure-redis \
        username="vault-edu" rotation_period="5m"
Success! Data written to: database/static-roles/static-account
````

To retrieve the credentials for the vault-edu user

```bash
$ vault read database/static-creds/static-account
Key                    Value
---                    -----
last_vault_rotation    2020-12-20T10:39:49.647822-06:00
password               ylKNgqa3NPVAioBf-0S5
rotation_period        5m
ttl                    3m59s
username               vault-edu
```

## Developing

You can run `make dev` in the root of the repo to start up a development vault server and automatically register a local build of the plugin. You will need to have a built `vault` binary available in your `$PATH` to do so.
