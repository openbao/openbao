---
title: "OpenBao Features - Transactional Storage"
description: "Blog series describing OpenBao's features. This episode focuses on transactional storage."
slug: features-transactional-storage
authors: cipherboy
tags: [features, storage, technical]
---

This is second part of a [multi-part series on OpenBao's features](/blog/tags/features).

Today we focus on [transactional storage](/community/rfcs/transactions/). While
the [earlier](./2024-10-16-transactions.md) blog [posts](./2024-10-27-transaction-details.md)
focused on the what and how of transactions in Raft, this post will focus on
the measurable impact of transactions in OpenBao and their lack in Vault. We
will demo some possible ways of creating snapshots which cannot restore and
are not consistent on Vault and show how we used transactions to achieve
consistency on OpenBao.

<!-- truncate -->

## Historical context

Recall from [last week's post](./2026-07-01-paginated-lists.md) that our
starting storage interface was rather limited:

```go
// Storage is the way that logical backends are able read/write data.
type Storage interface {
    List(context.Context, prefix string) (entries []string, err error)
    Get(context.Context, path string) (entry *StorageEntry, err error)
    Put(context.Context, entry *StorageEntry) error
    Delete(context.Context, path string) error
}
```

(from [`fork-point:sdk/logical/storage.go`](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/sdk/logical/storage.go#L31-L37)).

Also included in the storage model of the fork, though implemented in only
a few backends (Raft, CockroachDB, Consul, FoundationDB, and Spanner) was a
basic batch application mechanism:

```go
// TxnEntry is an operation that takes atomically as part of
// a transactional update. Only supported by Transactional backends.
type TxnEntry struct {
	Operation Operation
	Entry     *Entry
}

...

// Transactional is an optional interface for backends that
// support doing transactional updates of multiple keys. This is
// required for some features such as replication.
type Transactional interface {
	// The function to run a transaction
	Transaction(context.Context, []*TxnEntry) error
}
```

(from [`fork-point:sdk/physical/transactions.go`](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/sdk/physical/transactions.go#L13-L30)).

Notably, from the [implementation of
`physical.GenericTransactionHandler`](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/sdk/physical/transactions.go#L46-L153),
we see that this was not an implementation of check-and-set semantics: `LIST`
operations are entirely ignored, any `GET` operations are dispatched ahead of
any writes, and while a rollback log is created and entries read before
issuing any writes, they are not compared against any sent writes. This makes
batch application rather unsafe if used incorrectly: if a (distributed) lock
mechanism or other exclusive ownership semantic does not exist, multiple
in-flight transactions can write to the same storage entries. This may produce
unexpected results.

Luckily, this mechanism was not exposed at the logical level, hiding its use
within Core and all auth and secret plugins, preventing its misuse.

From [commit messages](https://github.com/openbao/openbao/commit/c1cf97adac5c53301727623a74b828a5f12592cf)
we can guess this mechanism was an internal implementation detail of the
[proprietary Vault Enterprise Performance Replication
mode](https://support.hashicorp.com/hc/en-us/articles/20457140183443-Replication-Overview-and-Merkle-Sync-Loop-Analyses)
and thus not relevant to improving snapshot consistency.

OpenBao instead moved to a much more powerful interactive transaction model:

```go

// Transactional is an optional interface for backends that support
// interactive (mixed code & statement) transactions in a similar
// style as Go's Database paradigm. This is equivalent to
// physical.Transactional, not the earlier, one-shot version of the
// interface.
type Transactional interface {
	// This function allows the creation of a new interactive transaction
	// handle, only supporting read operations. Attempts to perform write
	// operations (Put(...) or Delete(...)) will err.
	BeginReadOnlyTx(ctx context.Context) (txn Transaction, err error)

	// This function allows the creation of a new interactive transaction
	// handle, supporting read/write transactions. In some cases, the
	// underlying physical storage backend cannot handle parallel read/write
	// transactions.
	BeginTx(ctx context.Context) (txn Transaction, err error)
}

// Transaction is an interactive transactional interface: backend storage
// operations can be performed, and when finished, Commit or Rollback can
// be called. When a read-only transaction is created, write calls (Put(...)
// and Delete(...)) will err out.
type Transaction interface {
	Storage

	// Commit a transaction; this is equivalent to Rollback on a read-only
	// transaction. Either Commit or Rollback must be called to release
	// resources.
	Commit(ctx context.Context) error

	// Rollback a transaction, preventing any changes from being persisted.
	// Either Commit or Rollback must be called to release resources.
	Rollback(ctx context.Context) error
}
```

(from [`main:sdk/logical/storage_transactions.go`](https://github.com/openbao/openbao/blob/main/sdk/logical/storage_transactions.go#L10-L43)).

Callers of this API can perform arbitrary storage operations interleaved with
non-storage calls and have consistency amongst all of them. This is
implemented in both supported storage backends, Raft and PostgreSQL.

## Reproducers

Looking at plugin code in our [`fork-point` tag](https://github.com/openbao/openbao/tree/fork-point/builtin),
any series of multi-write flow could potentially be affected by a snapshot
consistency issue. However, to be affected by snapshot consistency issues,
the server needs to assume that either both writes succeeded or neither did.

### PKI

One such is in the PKI engine.

When creating a new issuer via `<mount>/root/generate/internal`, the [following
storage operations](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/path_root.go#L256-L320)
are performed:

 1. `config/key/<id>`, to [store the new root CA's key](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/storage.go#L437-L440)
 2. `config/keys`, to [store the new default issuer config](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/storage.go#L509-L511)
 3. `config/issuer/<id>`, to [import the new root CA's certificate](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/storage.go#L907-L911)
 4. `config/issuers`, to [store the new default issuer config](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/storage.go#L920-L922)
 5. `crls/<id>`, to [store the initial empty CRL](https://github.com/openbao/openbao/blob/8993802145833ab01d49c6070d787a9eccb81546/builtin/logical/pki/crl_util.go#L2197-L2203)

Notably consistency between storage operations 3 and 4 are the crucial:
failure to store the initial issuer's identifier as default will mean that
API compatibility with older Vault versions (and many third-party
applications) which are not aware of multi-issuer features is broken. This
will cause the API to return an error like:

```
err=Error making API request.

URL: GET http://localhost:8200/v1/058a0c0f-2dc3-a4a3-2e22-b00811700bac/issuer/default
Code: 500. Errors:

* 1 error occurred:
        * no default issuer currently configured

resp=<nil>
```

which will persist on all operations until an operator manually creates an
[association between the generated issuer and the
`default`](/api-docs/secret/pki/#set-issuers-configuration). Similar issues
could occur whenever an issuer is rotated; the key could be persisted but the
signing certificate could be dropped from the backup.

Notably, PKI's usage here would be a poor fit for check-and-set semantics:
composability of `importKey` and `importIssuer` into `writeCaBundle` would
be difficult to achieve while retaining transactional properties. This is why
the stronger interactive transaction model is better for OpenBao's use case,
even though it limits the theoretical storage backends one could implement
as not every potential storage engine (like S3) implements interactive
transactions.
