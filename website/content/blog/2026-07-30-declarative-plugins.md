---
title: "OpenBao Features - Declarative Plugins"
description: "Blog series describing OpenBao's features. This episode focuses on declarative plugin distribution and registration in OpenBao."
slug: features-declarative-plugins
authors: cipherboy
tags: [features, plugins, technical]
---

This is the fourth part of a [multi-part series on OpenBao's features](/blog/tags/features).

[Last time](./2026-07-21-declarative-configuration.md) we talked about how to
declaratively configure audit devices and initialize OpenBao. We saw how this
made integration of OpenBao in a wider ecosystem or product (such as
[EdgeX](2025-03-18-edgex-selects-openbao.md)) easier.

Like the last part, this part focuses on the operator experience, but for
consumption of OpenBao's plugins: auth methods, secrets engines, auto-unseal
devices, and more.

Our motivation here is to build towards a more [OpenTofu](https://opentofu.org/)-like,
extensible ecosystem. Easier consumption, [community-maintained
plugins](https://github.com/openbao/openbao-plugins), and a future plugin
registry will lead to more developers writing plugins and expand the
usefulness of OpenBao for everyone.

:::tip[Question]

What integrations would you like OpenBao to have? How would you like to see
writing plugins made easier?

[Contact us](https://github.com/openbao#contact) to share your thoughts or
contribute to the ecosystem!

::::

<!-- truncate -->

## Overview

Nearly everything within OpenBao is pluggable. OpenBao supports several types of plugins currently:

| Type            | Description                                                                                                                                                                   |
| :-------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Auth**        | Allow bringing sources of identity--JWTs, certificates, passwords--and exchanging them for OpenBao tokens.                                                                    |
| **Secret**      | Allow generating credentials (whether passwords for databases, PKI certificates, static secrets, and more) and protected through OpenBao's tokens and authorization policies. |
| **Database**    | Implement database-specific logic for updating and managing access for use with the `database` dynamic secret engine.                                                         |
| **KMS**         | Implement specialized interfaces for using HSM and KMS devices (such as YubiHSM or GCP CloudKMS) for auto-unseal (and external keys in the upcoming v2.7.0).                  |

Plugins have two primary classifications:

| Classification | Description                                                                                                                                                                 |
| :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Builtin**    | Distributed as part of the main `bao` binary artifact. No external process is started.                                                                                      |
| **External**   | Distributed as stand-alone binaries, requiring installation and configuration to use. Spawns an external process (managed by the OpenBao server) to handle plugin requests. |

For example, [`secrets-pki`](/docs/secrets/pki) is a **builtin** **secret**
plugin, but [`secrets-aws`](https://github.com/openbao/openbao-plugins/releases?q=secrets-aws-&expanded=true)
is an **external** **secret** plugin. [`auth-aws`](https://github.com/openbao/openbao-plugins/releases?q=auth-aws-&expanded=true)
also exists and is an **external** **auth** plugin.

## Usage

OpenBao since [v2.5.x](/community/release-notes/2-5-0/#v250) supported
[declarative plugin configuration](/docs/configuration/plugins/). Three
mandatory configuration [parameters](/docs/configuration/#parameters) are
required for these demos:

```hcl
// Only plugins from the specified directory will be loaded. This helps
// to prevent arbitrary binaries from being executed and leading to
// generalized RCE.
plugin_directory = "/openbao/plugins"

// Setting this allows the server process to automatically download new
// plugins if they're not registered. Otherwise OpenBao will not contact
// the internet by default. This will occur on all nodes (active and
// standby).
plugin_auto_download = true

// Setting this allows automatic registration of the plugin into the
// plugin catalog. This is allows operators to immediately use the plugin
// without having to manually register it using API commands:
//
// https://openbao.org/docs/api/system/plugins-catalog/
plugin_auto_register = true
```

With that in mind, adding an external plugin is greatly simplified:

```hcl
// Defines a new secret engine, named "aws".
plugin "secret" "aws" {
    // ## Distribution Information ##

    // Image is the container registry's address. It is strongly recommended
    // to pull from a trusted, local registry mirror instead of a public
    // registry.
    //
    // See also: https://github.com/openbao/openbao-plugins/pkgs/container/openbao-plugin-secrets-aws/1056268559?tag=v0.3.1
    image = "ghcr.io/openbao/openbao-plugin-secrets-aws"

    // The version of the plugin itself; must be a semantic version and also a
    // tag on the above registry.
    //
    // See also: https://semver.org/
    version = "v0.3.1"

    // Within the image, the path to the plugin binary. For OpenBao's
    // community maintained plugins, this is the same as the plugin itself.
    binary_name = "openbao-plugin-secrets-aws"

    // ## Execution Information ##

    // This contains the hash of the plugin binary and is required regardless
    // of distribution mechanism.
    //
    // If the above registry were to change the tag to point at a different
    // version of the image, this sha256sum prevents us from pulling an
    // unexpected plugin binary.
    sha256sum = "641ae1858c0f660b4c3761286d627e1dcfd33dc35e7c83eb81ca9050b5bdc6d8"

    // args = [ ... ] and env = [ ... ] are optional parameters if the plugin
    // requires additional information.
}
```

...and send a `SIGHUP` or restart the server. That's it! You should now see
messages in the server logs like:

```hcl
[INFO]  plugins: starting OCI plugin downloading
[DEBUG] plugins: processing plugin: plugin=secret-aws url=ghcr.io/openbao/openbao-plugin-secrets-aws:v0.3.1 binary_name=openbao-plugin-secrets-aws
[INFO]  plugins: downloading plugin from OCI registry: plugin=secret-aws url=ghcr.io/openbao/openbao-plugin-secrets-aws:v0.3.1
[DEBUG] plugins: local platform: plugin=secret-aws platform=linux/amd64
[DEBUG] plugins: extracting plugin from OCI image: plugin=secret-aws target=/openbao/plugins/.oci-cache/secret-aws/641ae185/openbao-plugin-secrets-aws binary=openbao-plugin-secrets-aws
[INFO]  plugins: found plugin binary in OCI image: plugin=secret-aws entry=openbao-plugin-secrets-aws size=25161890
[DEBUG] plugins: successfully extracted plugin binary: plugin=secret-aws path=/openbao/plugins/.oci-cache/secret-aws/641ae185/openbao-plugin-secrets-aws size=25161890
[INFO]  plugins: successfully downloaded and validated plugin: plugin=secret-aws cached_path=/openbao/plugins/.oci-cache/secret-aws/641ae185/openbao-plugin-secrets-aws symlink_path=/openbao/plugins/secret-aws-v0.3.1 hash=641ae1858c0f660b4c3761286d627e1dcfd33dc35e7c83eb81ca9050b5bdc6d8
[INFO]  plugins: OCI plugin downloading completed
```

It will now show up in the plugin catalog:

```shell
$ bao read -field=secret sys/plugins/catalog
[aws kubernetes kv ldap openldap pki rabbitmq ssh totp transit]
```

and the plugin can be enabled:

```shell
$ bao secrets enable -path team/creds/aws aws
Success! Enabled the aws secrets engine at: team/creds/aws/
```

Looking at the storage layout, we see that the plugin was downloaded and
placed in the plugin folder as requested:

```shell
$ tree -alh plugins/
[  100]  plugins/
├── [   66]  .oci-cache
│   └── [   16]  secret-aws
│       └── [   52]  641ae185
│           └── [  24M]  aws
└── [   80]  secret-aws-v0.3.1 -> .oci-cache/secret-aws/641ae185/aws
```

:::info

Even if you don't want to automatically download plugins as part of the server
process, you can invoke the standalone `bao plugin` CLI to perform downloads
and still benefit from declarative configuration and OCI-based plugin
distribution:

```
$ bao plugin init -config /openbao
[INFO]  Plugin directory: /openbao/plugins
[INFO]  Found 1 OCI plugin(s) in configuration
[INFO]  downloading plugin from OCI registry: plugin=secret-aws url=ghcr.io/openbao/openbao-plugin-secrets-aws:v0.3.1
[INFO]  found plugin binary in OCI image: plugin=secret-aws entry=openbao-plugin-secrets-aws size=25161890
[INFO]  successfully downloaded and validated plugin: plugin=secret-aws cached_path=/openbao/plugins/.oci-cache/secret-aws/641ae185/openbao-plugin-secrets-aws symlink_path=/openbao/plugins/secret-aws-v0.3.1 hash=641ae1858c0f660b4c3761286d627e1dcfd33dc35e7c83eb81ca9050b5bdc6d8
```

:::

This pattern applies for secret, auth, and database plugins. When using kms
plugins, note that the plugin will not show up in the plugin catalog (shown
above) but will be usable at startup:

```hcl
plugin "kms" "pkcs11" {
    image = "ghcr.io/openbao/openbao-plugin-kms-pkcs11"
    version = "v0.1.0"
    binary_name = "openbao-plugin-kms-pkcs11"
    sha256sum = "55245882727535579e710672f0eae1bcdddc846006db857baaa6e09e33d40faf"
}

seal "pkcs11" {
    lib = "/usr/lib64/softhsm/libsofthsm.so"
    token_label = "OpenBao"
    pin = "4321"
    key_label = "bao-root-key-rsa"
    rsa_oaep_hash = "sha1"
}
```

## Next steps

Check our [updated documentation on plugins](/docs/next/plugins) and
[configuration reference](/docs/next/configuration/plugins).

Tune in next time for a post on recursive listing, one of HashiCorp Vault's
[most requested features](https://github.com/hashicorp/vault/issues/5275).
