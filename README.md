# Vault Plugin: Kerberos Auth Backend
[![Travis Build Status](https://travis-ci.org/wintoncode/vault-plugin-auth-kerberos.svg?branch=master)](https://travis-ci.org/wintoncode/vault-plugin-auth-kerberos)

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for users to authenticate with Vault via Kerberos.

## Usage

### Authentication

You can authenticate by posting a valid SPNEGO Negotiate header to `/v1/auth/kerberos/login`.

```python
try:
    import kerberos
except:
    import winkerberos as kerberos
import requests

service = "HTTP/vault.domain@YOUR-REALM.COM"
rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
kerberos.authGSSClientStep(vc, "")
kerberos_token = kerberos.authGSSClientResponse(vc)

r = requests.post("https://vault.domain:8200/v1/auth/kerberos/login",
                  json={'authorization': 'Negotiate ' + kerberos_token})
print('Vault token:', r.json()['auth']['client_token'])
```

### Configuration

1. Install and register the plugin.

Put the plugin binary (`vault-plugin-auth-kerberos`) into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```json
...
plugin_directory = "path/to/plugin/directory"
...
```

```sh
$ vault write sys/plugins/catalog/kerberos-auth-plugin sha_256="$(shasum -a 256 'vault-plugin-auth-kerberos' | cut -d ' ' -f1)" command="vault-plugin-auth-kerberos -client-cert server.crt -client-key server.key"
```

2. Enable the Kerberos auth method:

```sh
$ vault auth-enable -path=kerberos -plugin-name=kerberos-auth-plugin plugin
Successfully enabled 'kerberos' at 'kerberos'!
```

3. Use the /config endpoint to configure Kerberos.

Create a keytab for the kerberos plugin:
```sh
$ ktutil
ktutil:  addent -password -p your_service_account@REALM.COM -e aes256-cts -k 1
Password for your_service_account@REALM.COM:
ktutil:  list -e
slot KVNO Principal
---- ---- ---------------------------------------------------------------------
   1    1            your_service_account@REALM.COM (aes256-cts-hmac-sha1-96)
ktutil:  wkt vault.keytab
```

Then base64 encode it:
```sh
base64 vault.keytab > vault.keytab.base64
```

```sh
vault write auth/kerberos/config keytab=@vault.keytab.base64 service_account="your_service_account"
```

4. Optionally configure LDAP backend to look up Vault policies.
Configuration for LDAP is identical to the [LDAP](https://www.vaultproject.io/docs/auth/ldap.html)
auth method, but writing to to the Kerberos endpoint:

```sh
vault write auth/kerberos/config/ldap @vault-config/auth/ldap/config
vault write auth/kerberos/groups/example-role @vault-config/auth/ldap/groups/example-role
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into
`$GOPATH/src/github.com/wintoncode/vault-plugin-auth-kerberos`.
You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```json
...
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog):

```sh
$ vault write sys/plugins/catalog/kerberos \
        sha_256=<expected SHA256 Hex value of the plugin binary> \
        command="vault-plugin-auth-kerberos"
...
Success! Data written to: sys/plugins/catalog/kerberos
```

Note you should generate a new sha256 checksum if you have made changes
to the plugin. Example using openssl:

```sh
openssl dgst -sha256 $GOPATH/vault-plugin-auth-kerberos
...
SHA256(.../go/bin/vault-plugin-auth-kerberos)= 896c13c0f5305daed381952a128322e02bc28a57d0c862a78cbc2ea66e8c6fa1
```

Enable the auth plugin backend using the Kerberos auth plugin:

```sh
$ vault auth-enable -plugin-name='kerberos' plugin
...

Successfully enabled 'plugin' at 'kerberos'!
```

#### Tests

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the tests.

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```

