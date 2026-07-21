---
title: "OpenBao Features - Declarative Configuration"
description: "Blog series describing OpenBao's features. This episode focuses on declarative configuration of OpenBao."
slug: features-declarative-configuration
authors: cipherboy
tags: [features, storage, technical]
---

This is the third part of a [multi-part series on OpenBao's features](/blog/tags/features).

In the past few parts, we talked about low-level technical features that
OpenBao core maintainers and plugin authors can take advantage of to make
secrets management safer and more scalable.

This part focuses on something that applies to operators of OpenBao: better
operator experience for initial configuration. We focus on one question:

:::tip[Question]

**How can we make OpenBao deployment easier and more reproducible?**

:::

<!-- truncate -->

The answer lies in [declarative self-initialization](/docs/configuration/self-init/)
and [declarative audit device creation](/docs/configuration/audit).

These features [available since OpenBao v2.4.0](/community/release-notes/2-4-0/#features)
allow operators to define the state of OpenBao prior to deploying it.

## Audit Devices

Sensitive programs like Vault and OpenBao should always have audit logs.
Ideally it would be hard to not them set up without audit logs, or at least,
make it very hard to do so.

However, the API model of Vault made this difficult originally:

1. Operators would call [`sys/init`](/api-docs/system/init/) to create seal
   information and return a root token.
2. Operators would then have to call [`sys/audit`](/api-docs/system/audit/) to
   create an audit device.

In the meantime, they'd want to be configuring OpenBao: creating auth mounts,
policies, secret engines, and the like. Perhaps this was fully automated, like
in OpenTofu, and it would be hard to [guarantee a strict
ordering](https://opentofu.org/docs/internals/graph/#walking-the-graph), due
to inherent parallelism.

Motivating us to solve this was one of the few [remote code execution
vulnerabilities (RCEs)](https://discuss.hashicorp.com/t/hcsec-2025-14-privileged-vault-operator-may-execute-code-on-the-underlying-host/76033)
in Vault: audit device configuration frequently interacted with the broader
environment, including potentially in ways that lead to RCEs. While HashiCorp
opted just to [patch one small hole](https://developer.hashicorp.com/vault/docs/configuration#allow_audit_log_prefixing),
we opted to reimagine how audit device configuration could be controlled by
configuration owners.

Thus [declarative audit devices](/community/rfcs/config-audit-devices/) were
born.

Here, system operators--those with privileged access to the underlying
configuration and broader execution environment--can define audit devices
through configuration files, reloading them on `SIGHUP`. These look like
the following:

```hcl
audit "file" "my-device" {
    description = "This audit device writes to stdout which never fails."
    options {
        file_path = "stdout"
    }
}
```

While writing to `stdout` doesn't matter as much, consider the implications
when writing to [network devices](/docs/audit/socket/): operators can
[disable API-driven creation](/docs/configuration/#parameters) by setting
`unsafe_allow_api_audit_creation = false` (the default) and ensure that a
leaked admin token doesn't result in secrets being exfiltrated to an attacker
over the network.

As an added bonus, every single request is now audited after initialization,
including any declarative self-initialization requests that we'll see below.

## Self-Initialization

Going hand-in-hand with configuration-driven audit devices is [declarative
self-initialization](/docs/configuration/self-init/).

Here, operators define requests that they want executed on startup:

```hcl
initialize "authentication" {
    request "mount-userpass" {
        path      = "sys/auth/userpass"
        operation = "create"
        data = {
            type        = "userpass"
            description = "Administrative access to OpenBao."
        }
    }

    request "create-user" {
        path      = "auth/userpass/users/admin"
        operation = "create"
        data = {
            password = {
                eval_source = "env"
                eval_type = "string"

                // Read the initial administrator password from an
                // environment variable.
                env_var = "INITIAL_ADMIN_PASSWORD"
                require_present = true
            }

            token_policies = ["admin"]
        }
    }

    request "create-policy" {
        operation = "create"
        path = "sys/policies/acl/admin"
        data = {
            policy = <<EOP

path "*" {
  capabilities = ["create", "update", "patch", "read", "delete", "list", "scan", "sudo"]
}

EOP

        }
    }
}
```

This would:

1. Create a new `auth/userpass` mount,
2. Create an administrative user, and
3. Create a highly privileged policy for that user.

While this may not look that different from an operator running commands
manually, consider the implications for OpenBao as a building block of some
larger system. This system would need:

- A source of identity, to tie OpenBao into;
- A KMS or similar auto-unseal device (including `static`) to automate
  unseal;
- A service orchestration layer (whether systemd unit files or Kubernetes),
- A system to manage day one OpenBao operations.

Given those exist, operators can provision the initial state fully
declaratively.

OpenBao gives operators several tools for interacting in the form of [dynamic
data source](/docs/concepts/profiles/#value-types-and-dynamic-data-sources).
These can be [environment variables](/docs/concepts/profiles/#env-source):

```hcl
password = {
    eval_source = "env"
    eval_type = "string"

    // Read the initial administrator password from an
    // environment variable.
    env_var = "INITIAL_ADMIN_PASSWORD"
    require_present = true
}
```

or [files](/docs/concepts/profiles/#file-source):

```hcl
policy = {
    eval_source = "file"
    eval_type = "string"

    path = "/path/to/admin-policy.hcl"
}
```

OpenBao also supports chaining from the value of past
[requests](/docs/concepts/profiles/#request-source) or
[responses](/docs/concepts/profiles/#response-source):

```hcl
entity_id = {
    eval_source = "response"
    eval_type = "string"

    initialize_name = "identity"
    response_name = "entity"
    field_selector = ["data", "id"]
}
```

and can do [CEL](/docs/concepts/profiles/#cel-source) or
[`text/template`](/docs/concepts/profiles/#template-source)
based templating:

```hcl
path = {
    eval_source = "template"
    eval_type = "string"

    template = "auth/userpass/users/{{ .input.username }}"
}
```

This allows construction of fairly advanced configurations and interactions
with nearly every subsystem regardless of complexity.

Think of self-initialization like the building block of a fully reproducible
environment: operators define the minimal configuration necessary to stand
up OpenBao and then systems like [OpenTofu](https://opentofu.org) can take
over from there.

:::info

Self-initialization has three design limitations:

1. It is intentionally only run on first startup. This ensures that an
   attacker can't later modify the configuration and grant themselves
   privileged access.
2. Only a single node should be started to do self-initialization; parallel
   self-initialization is not supported and may fail or lead to slit-brained
   Raft clusters.
3. Operators need to be running auto-unseal so that initial startup is fully
   automatic.

:::
