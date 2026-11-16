---
title: "OpenBao Features - Recursive Lists (SCAN) & Filtering"
description: "Blog series describing OpenBao's features. This episode focuses on recursive list support via the new SCAN keyword."
slug: features-recursive-list
authors: cipherboy
tags: [features, list, technical]
---

This is the fifth part of a [multi-part series on OpenBao's features](/blog/tags/features).

[Last time](./2026-07-30-declarative-plugins.md) we talked about declarative
plugin configuration and how it made deploying and adopting plugins much
easier. With OCI-based distribution operators can deploy plugins with just a
few configuration snippets, mirroring OpenTofu's approach.

We hinted at addressing two of the [most-requested features](https://github.com/hashicorp/vault/issues?q=is%3Aissue%20sort%3Areactions-desc)
in HashiCorp Vault: [recursive list support](https://github.com/hashicorp/vault/issues/5275)
and [filtering of list responses](https://github.com/hashicorp/vault/issues/5362).

As mentioned there [by Vault community members](https://github.com/hashicorp/vault/issues/5275#issuecomment-2920932325),
we've supported recursive lists [since
OpenBao v2.2.0](/community/release-notes/2-2-0/#220) and
[filtered lists since OpenBao v2.4.0](/community/release-notes/2-4-0/#240).
And, for any plugin developers out there, [we support it in our external plugin
SDK](https://pkg.go.dev/github.com/openbao/openbao/sdk/v2/logical#Operation)
including [storage helpers which should work on Vault
as well](https://pkg.go.dev/github.com/openbao/openbao/sdk/v2/logical#ScanView).

:::tip[Question]

What other places need recursive list support?

[Reach out to us](https://github.com/openbao#contact) if we've missed one!

::::

<!-- truncate -->

## Overview

OpenBao has always supported a custom HTTP verb, `LIST`, for listing entries
under a path. This is also supported via the `?list=true` [query
parameter](/docs/api/#api-operations) on a regular `GET`-verb request, for use
when clients cannot support custom verbs.

In designing [recursive listing](/community/rfcs/scan-operation), we realized
many endpoints (like [KVv2's list entries](/docs/api/secret/kv/kv-v2/#list-secrets))
made sense as both `LIST` and `SCAN` operations. Rather than forcing authors
to implement a new endpoint design--for example, moving from a layout like
`LIST /secrets/metadata/:path` to `LIST /secrets/metadata-recursive/:path`--we
opted to introduce a new verb, `SCAN` for this. This allowed us to extend ACL
policies to allow policy authors control over recursive lists without having
to investigate a plugin's layout.

For instance, the policy:

```hcl
path "secrets/*" {
    capabilities = ["read", "create", "update", "list", "patch", "delete"]
}
```

gives users the ability to perform mostly cheap operations, while restricting
their ability to do recursive lists (scan operations). However, if they
also add the scan operation:

```hcl
path "secrets/*" {
    capabilities = ["read", "create", "update", "list", "patch", "scan", "delete"]
}
```

this would be more expensive and maybe should only be allowed on specific
subdirectories within a KVv2 layout:

```hcl
path "secrets/metadata/my-app/*" {
    capabilities = ["read", "create", "update", "list", "patch", "scan", "delete"]
}
```

## Usage

As we discussed in past blogs, OpenBao has support for both
[pagination](./2026-07-01-paginated-lists.md) and [transactional
storage](2026-07-09-transactional-storage.md). When coupled with
`SCAN` support, this gives users a powerful consistency tool to inspect
a large number of secrets at once. For instance, the API call:

```
SCAN secrets/detailed-metadata/my-app
```

would return a list response with metadata about each secret as well. While
this would usually be a 1+n operation in Vault (list all secret and then
fetch its metadata), OpenBao will return them in a single operation, with a
transaction to ensure internal consistency of the results.

The same holds true for namespaces: `bao namespace list` will show all
top-level children of the current namespace, but `bao namespace scan` will
recurse and show children-of-children and the full hierarchy.

OpenBao also supports the `scan` operation via the `bao scan` command or
in the [Go API via `client.Logical().Scan(...)`](https://pkg.go.dev/github.com/openbao/openbao/api/v2#Logical.Scan)
and related operations.

## Security

This ties into another [commonly requested feature in HashiCorp
Vault](https://github.com/hashicorp/vault/issues/5362): restricting [list (and
now scans!)](/community/rfcs/filtering-list/) to entries which the user can view.

In OpenBao, we [implemented a policy keyword](/docs/concepts/policies/#filtering-list-or-scan-results),
`list_scan_response_keys_filter_path`, which takes a
[`text/template`](https://pkg.go.dev/text/template) expression for limiting
visible results. Visible results are entries which (when templating is applied
according to the filter path) have list access for entries ending in a `/` or
read access otherwise. This means the policy author must know the
corresponding type of the plugin and where to map list entries to. For
example in KVv2, one could either map entries in a list or scan to the data
(`<mount>/data/<entry>`) or metadata (`<mount>/metadata/<entry>`) paths.

Consider an ACL policy like:

```hcl
# Allow listing secrets broadly but limit to visible results (read or list):
path "secrets/metadata/*" {
    capabilities = ["list", "scan"]

    # See also: https://openbao.org/docs/concepts/policies/#filtering-list-or-scan-results
    list_scan_response_keys_filter_path = "{{ .path }}{{ .key }}"
}

# Allow reading secrets and metadata in shared:
path "secrets/data/shared/*" {
    capabilities = ["read"]
}

path "secrets/metadata/shared/*" {
    capabilities = ["read"]
}

# But allow full access to a personal space.
path "secrets/data/personal/*" {
    capabilities = ["read", "create", "update", "list", "patch", "scan", "delete"]
}

path "secrets/metadata/personal/*" {
    capabilities = ["read", "create", "update", "list", "patch", "scan", "delete"]
}
```

In this example, a call to the scan endpoint would show entries under `shared/`
and `personal/` but hide entries under `private/` due to the filtering on the
list result.

Use of `text/template` allows for advanced functionality like changing the path
as well; for instance, if metadata wasn't widely used but direct secret access
should be the control, `list_scan_response_keys_filter_path` could be written
as:

```json
{{ .path | replace "secrets/metadata/" "secrets/data/" }}{{ .key }}
```

because the list and scan endpoints are under `/metadata/` and not `/data/`.

## Looking ahead

Going forward, we'll likely consider supporting `Scan(...)` and
`ScanWithData(...)` as part of our formal storage interface, allowing easier
implementation for plugins.

Tune in next time as we explore ACME-enabled TLS listeners!
