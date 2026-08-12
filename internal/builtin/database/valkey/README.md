# plugin-database-valkey

An [OpenBao](https://openbao.org) plugin for Valkey

This plugin should be compatible with Redis.

This project uses the database plugin interface introduced in Vault version 0.7.1.

The plugin supports the generation of static and dynamic user roles and root credential rotation on a stand alone valkey server.

## Build

Use `make dev` to build a development version of this plugin.

**Please note:** In case of the following errors, while creating Valkey connection in Vault, please build this plugin with `CGO_ENABLED=0 go build -ldflags='-extldflags=-static' -o vault-plugin-database-valkey ./cmd/vault-plugin-database-valkey/` command. More details on this error can be found [here](https://github.com/hashicorp/vault-plugin-database-valkey/issues/1#issuecomment-1078415041).
````bash
Error writing data to database/config/my-valkey: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/config/my-valkey
Code: 400. Errors:

* error creating database object: invalid database version: 2 errors occurred:
        * fork/exec /config/plugin/vault-plugin-database-valkey: no such file or directory
        * fork/exec /config/plugin/vault-plugin-database-valkey: no such file or directory
````

## Testing
To run tests, `go test` will first set up the docker.io/valkey/valkey:latest database image, then execute a set of basic tests against it. To test against different valkey images, for example 5.0-buster, set the environment variable `VALKEY_VERSION=5.0-buster`. If you want to run the tests against a local valkey installation or an already running valkey container, set the environment variable `TEST_VALKEY_HOST` before executing. 

**Note:** The tests assume that the valkey database instance has a default user with the following ACL settings `user default on >default-pa55w0rd ~* +@all`. If it doesn't, you will need to align the Administrator username and password with the pre-set values in the `valkey_test.go` file.

Set `VAULT_ACC=1` to execute all of the tests including the acceptance tests, or run just a subset of tests by using a command like `go test -run TestDriver/Init` for example.

## Installation

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the
`vault-plugin-database-valkey` executable generated above, into the directory.

**Please note:** This plugin is incompatible with Vault versions before 1.6.0 due to an update of the database plugin interface. You will be able to register the plugin in the plugins catalog with an older version of Vault but when you try to initialize the plugin to connect to a database instance you will get this error.
````bash
Error writing data to database/config/my-valkey: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/config/my-valkey
Code: 400. Errors:

* error creating database object: Incompatible API version with plugin. Plugin version: 5, Client versions: [3 4]
````

Sample commands for registering and starting to use the plugin:

```bash
$ SHA256=$(shasum -a 256 plugins/vault-plugin-database-valkey | cut -d' ' -f1)

$ vault secrets enable database

$ vault write sys/plugins/catalog/database/vault-plugin-database-valkey sha256=$SHA256 \
        command=vault-plugin-database-valkey
```

At this stage you are now ready to initialize the plugin to connect to the valkey db using unencrypted or encrypted communications.

Prior to initializing the plugin, ensure that you have created an administration account. Vault will use the user specified here to create/update/revoke database credentials. That user must have the appropriate rule `+@admin` to perform actions upon other database users.

### Plugin Initialization

#### Standalone VALKEY Server.

```bash
$ vault write database/config/my-valkey plugin_name="vault-plugin-database-valkey" \
        host="localhost" port=6379 username="Administrator" password="password" \
        allowed_roles="my-valkey-*-role"

# You should consider rotating the admin password. Note that if you do, the new password will never be made available
# through Vault, so you should create a vault-specific database admin user for this.
$ vault write -force database/rotate-root/my-valkey

 ```

### Dynamic Role Creation

When you create roles, you need to provide a JSON string containing the Valkey ACL rules which are documented [here](https://valkey.io/commands/acl-cat) or in the output of the `ACL CAT` valkey command.

```bash
# if a creation_statement is not provided the user account will default to a read only user, '["~*", "+@read"]' that can read any key.
$ vault write database/roles/my-valkey-admin-role db_name=my-valkey \
        default_ttl="5m" max_ttl="1h" creation_statements='["+@admin"]'

$ vault write database/roles/my-valkey-read-foo-role db_name=my-valkey \
        default_ttl="5m" max_ttl="1h" creation_statements='["~foo", "+@read"]'
Success! Data written to: database/roles/my-valkey-read-foo-role
```

To retrieve the credentials for the dynamic accounts

```bash

$vault read database/creds/my-valkey-admin-role
Key                Value
---                -----
lease_id           database/creds/my-valkey-admin-role/OxCTXJcxQ2F4lReWPjbezSnA
lease_duration     5m
lease_renewable    true
password           dACqHsav6-attdv1glGZ
username           V_TOKEN_MY-VALKEY-ADMIN-ROLE_YASUQUF3GVVD0ZWTEMK4_1608481717

$ vault read database/creds/my-valkey-read-foo-role
Key                Value
---                -----
lease_id           database/creds/my-valkey-read-foo-role/Yn99BrX4t0NkLyifm4NmsEUB
lease_duration     5m
lease_renewable    true
password           ZN6gdTKszk7oc9Oztc-o
username           V_TOKEN_MY-VALKEY-READ-FOO-ROLE_PUAINND1FC5XQGRC0HIF_1608481734

```

### Static Role Creation

In order to use static roles, the user must already exist in the Valkey ACL list. The example below assumes that there is an existing user with the name "vault-edu". If the user does not exist you will receive the following error.

```bash
Error writing data to database/static-roles/static-account: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/static-roles/static-account
Code: 400. Errors:

* cannot update static account username

```

```bash
$ vault write database/static-roles/static-account db_name=insecure-valkey \
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

## Spring Cloud Vault Integration

> Tested on [spring-cloud-vault:3.1.0](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html)

In order to enable integration with `Spring Cloud Vault` and therefore supply dynamically-generated Valkey credentials to Spring applications, we can use `org.springframework.cloud:spring-cloud-vault-config-databases` with [Multiple Databases](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html/#vault.config.backends.databases) configuration approach.

Sample `application.yml` configuration (not-related sections are omitted):

```yaml
spring:
  cloud:
    vault:
      host: 127.0.0.1
      port: 8200
      authentication: TOKEN
      token: ${VAULT_TOKEN}
      databases:
        valkey:
          enabled: true
          role: my-valkey-role
          backend: database
          username-property: spring.valkey.username
          password-property: spring.valkey.password
  config:
    import: vault://
```

**Please note:** Spring Cloud Vault does not support `max_ttl` yet, thus we have to set it up to `0` when creating configurations. More details can be found [here](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html/#vault.config.backends.databases).

## Developing

A set of make targets are provided for quick and easy iterations when developing. These steps assume there is a Vault
server running locally and accessible via the `vault` CLI. See this [documentation](https://github.com/hashicorp/vault#developing-vault) 
on how to get started with Vault.

1. `make setup-env` will start a Valkey docker container and initialize a test user with the username `us3rn4m3` and passwod `user-pa55w0rd`
2. `source ./bootstrap/terraform/local_environment_setup.sh` will export the necessary environment variables generated from the setup step
3. `make configure` will build the plugin, register it in your local Vault server and run sample commands to verify everything is working
4. `make testacc` will run the acceptance tests against the Valkey container created during the environment setup
5. `make teardown-env` will stop the Valkey docker container with any resources generated alongside it such as network configs

When iterating, you can reload any local code changes with `make configure` as many times as desired to test the latest 
modifications via the Vault CLI or API.
