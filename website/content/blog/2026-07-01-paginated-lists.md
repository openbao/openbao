---
title: "OpenBao Features - Paginated Lists"
description: "Blog series describing OpenBao's features. This episode focuses on paginated lists."
slug: features-paginated-lists
authors: cipherboy
tags: [features, storage, technical]
---

This is the start of a [multi-part series on OpenBao's features](/blog/tags/features).

Nearly every single networked interface returning a list of results supports
subsets. SQL supports the [`LIMIT` and `OFFSET` keywords](https://www.postgresql.org/docs/current/queries-limit.html),
along with a rich language for filtering returned results. Google Cloud KMS
APIs [supports `pageSize`, yielding a `nextPageToken`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/list?rep_location=global),
for iterating over multiple pages of results.

Many resources in Vault and OpenBao return lists:
[KVv2 secrets](/api-docs/secret/kv/kv-v2/#list-secrets),
[PKI's certificate lists](/api-docs/secret/pki/#list-certificates),
[SSH's roles](/api-docs/secret/ssh/#list-roles), and more.

Paginated lists were shipped [in OpenBao v2.0.0](/community/release-notes/2-0-0/#200)
as our very first feature in our very first release!

So, why doesn't Vault support paginated lists?

<!-- truncate -->

The answer lies in its historical great-common-denominator storage interface:

```go
// Storage is the way that logical backends are able read/write data.
type Storage interface {
    List(context.Context, string) ([]string, error)
    Get(context.Context, string) (*StorageEntry, error)
    Put(context.Context, *StorageEntry) error
    Delete(context.Context, string) error
}
```

(from [`fork-point:sdk/logical/storage.go`](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/sdk/logical/storage.go#L31-L37)).

In supporting [over twenty different storage
backends](https://github.com/openbao/openbao/tree/fork-point/physical),
Vault had to support a common core of simple APIs over all potential storage
backends. This meant keeping `Storage.List(...)` to a simple get-all-results
list operation. If LIST APIs were to limit results, this would mean they'd
still have to fetch them all from storage and only limit them in memory before
sending to the client.

Early in OpenBao's history, the [decision was made](/community/policies/plugins/)
to remove all but the Raft storage backend. This made it possible to iterate
on our storage model. Concretely, [paginated lists](/community/rfcs/paginated-lists/)
and [transactional storage](/community/rfcs/transactions/) (to be discussed
another time!) came out of that. As we [re-introduced](/community/rfcs/postgresql/)
storage backends [like PostgreSQL](/docs/configuration/storage/postgresql/),
we made sure to include the improvements we've made to the storage API from
the start.

OpenBao's storage interface now looks like:

```go
// Storage is the way that logical backends are able read/write data.
type Storage interface {
	List(context.Context, string) ([]string, error)
	ListPage(context.Context, string, string, int) ([]string, error)
	Get(context.Context, string) (*StorageEntry, error)
	Put(context.Context, *StorageEntry) error
	Delete(context.Context, string) error
}
```

(from [`v2.5.5:sdk/logical/storage.go`](https://github.com/openbao/openbao/blob/v2.5.5/sdk/logical/storage.go#L35-L42))

meaning that API handlers can now fetch only a subset of results.

This follows a SQL-like interface:

```go
func (b *RaftBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	// ... implementation elided ...
}
```

(from [`v2.5.5:physical/raft/raft.go`](https://github.com/openbao/openbao/blob/v2.5.5/physical/raft/raft.go#L1716))

taking the new parameters `after` and `limit`. These are:

- `after`: an optional entry to begin listing after for pagination; not required to
  exist in the list results.
- `limit`: an optional number of entries to return; defaults to all entries
  when set to a non-positive number.

We suggest plugin authors pass these through on all API endpoints to the
underlying storage calls.

For plugin authors who build against OpenBao's SDK but wish to have
compatibility with HashiCorp Vault, we've [stubbed the
implementation](https://github.com/openbao/openbao/blob/v2.5.5/sdk/plugin/grpc_storage.go#L92-L115),
meaning you can safely expose and use a paginated list API and support it
on both server implementations.

In addition, use of paginated lists has lead to improvements like
[#678](https://github.com/openbao/openbao/pull/678) by Fatima Patel, to
use pagination during PKI's tidy operations. In the past, tidy operations
could consume a lot of memory if a large number of PKI mounts contained a
large number of stored leaf certificates. We exposed a new `page_size` option
(defaulting to 1000) to limit the number of certificate serial numbers in
memory during a single PKI tidy operation.

By enforcing this with [`pagination_limit`](/docs/concepts/policies/#limiting-pagination)
in an ACL policy, operators can now that clients use pagination and set
maximum result set sizes going forward.

In short, OpenBao aligns with long-standing industry expectations for
expensive list calls and operators have more control with OpenBao than with
Vault for managing the performance impact of these types of API requests.

Tune in next time for a discussion on [transactional storage](./2024-10-16-transactions.md)!
