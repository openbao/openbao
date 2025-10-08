---
title: Implementing Transactions in Raft
description: Analysis of OpenBao's Raft storage backend and implementing transactions in it.
slug: raft-transactions
authors: cipherboy
tags: [technical, raft, core]
image: https://raw.githubusercontent.com/openbao/artwork/refs/heads/main/color/openbao-text-color.svg
---

## Overview

OpenBao, like its upstream, favors the [`raft` internal storage engine](https://openbao.org/docs/configuration/storage/raft).
While more complex than relying on a database for replication, this storage
engine allows us to have lower latency on read operations, because it uses
a [local K/V implementation](https://github.com/etcd/bbolt) based on [B+-trees](https://en.wikipedia.org/wiki/B%2B_tree). For workloads
with low writes but high reads (typical of most uses of K/V secrets), this
trade off allows for the best performance.

An earlier [blog post](https://openbao.org/blog/transactions) talked about the availability of
transactions in the [`main` branch](https://github.com/openbao/openbao/tree/main), this post will focus on
the technical details of implementing transactions.

<!-- truncate -->

[Raft][raft-algo] is consensus protocol typically used in [databases][etcd]
and other distributed systems. Nodes in the algorithm are given voting
privileges, allowing them to select a single leader node and replace it if
it becomes unresponsive. This gives the Raft protocol availability. Only the
leader node is allowed to perform commands, which are writes in the case of
OpenBao. For a write to be applied, every node must acknowledge it, giving the
Raft protocol consistency. By running an odd number of nodes, we ensure a
unique election result in the case of disagreements.

In OpenBao, the [`raft` storage backend][raft-backend] is the combination of
an implementation of the [HashiCorp Raft library][hcp-raft] and the
[bbolt](https://github.com/etcd/bbolt) K/V store. When Raft applies a [WAL][]
entry, the underlying [FSM][raft-fsm] applies the corresponding operations.
Prior to transactions, these consisted of bare [Put and Delete
ops][storage-write]. Further, read requests were [handled
individually][storage-read], meaning there was no consistency between two
separate requests.

## Implementing transactions

In [introducing transactions][transaction-rfc], we thus needed an interface
which let us attach persistent state, such as an underlying [bbolt
transaction][bbolt-txn]. Notably, bbolt [only supports][bbolt-txn-limits] a
single non-exclusive write transaction and parallel read transactions.
Furthermore, opening a write transaction when the user wants a writable
storage isn't ideal as we need to ensure the values written to Raft are
correctly applied: we'd thus need to hold the write transaction even longer,
until Raft has finished applying, to be able to commit the underlying write
transaction. This blocks all other writes which may be occurring, such as
earlier Raft log entries.

Thus, we needed a hybrid design: use read transactions for consistency,
regardless of the transaction writeability, but send a complex operation
entry to Raft which allowed verifying that all operations which occurred
had not been impacted by any other in-flight operations.The Raft
implementation in OpenBao already supported complex operations and allowed
us to indicate a return value on individual operations. This let us safely
conflict a transaction by returning an error message to the requester, rather
than erring at the Raft FSM level, which would cause a panic and subsequent
leader election. In the case of our Raft implementation, transactions are
non-blocking to avoid potential implicit locking and thus subtle lock ordering
bugs and thus we'd prefer to have the caller retry the operation entirely if
it conflicted.

This gives us the equivalent of write committed transactions from standard
relational databases.

Our structured [transaction operation][txn-commit] thus looks like:

```
[
 { beginTxnOp }
 { ... verifyReadOp ... }
 { ... verifyListOp ... }
 { ... perform all writes ... }
 { commitTxnOp }
]
```

Here, for any write (a `Put(...)` or `Delete(...)`) or a `Get(...)`, we issue
a corresponding read on the underlying storage transaction. Into the log
entry, we save a message indicating both the read entry and the [hash of its
value][hash-value]. Similarly for `List(...)` operations, we also save the
underlying storage entries, but [include one additional entry][list-impl] past
the end of our results to ensure that we did not artificially exclude any
entries.

Doing this complicates our transaction's implementation: each write operation
must be cached so that future `List(...)` or `Get(...)` operations within the
transaction can be adjusted to return a consistent value. For `ListPage(...)`
in particular, this is made more complex by needing to efficiently synthesize
three data sources: the entries in the underlying bbolt transaction, any newly
written entries, and any deleted entries.

However, this additional bookkeeping work and using the underlying transaction
allows us to commit a minimal transaction: no unnecessary verified reads or
duplicate writes are sent via Raft.

On the other side, when the log is confirmed, [application][txn-apply] first
verifies that the current storage state matches the verified expectations and
refuses to perform any writes if it differs, returning a transaction commit
failure to the requester. This lets us avoid unnecessarily applying any write
operations: all logs within the batch are committed to bbolt using a single
[large transaction][batch-apply-txn] for performance and correctness w.r.t.
the expectations of the Raft protocol.

## Potential optimization as future work

When discussing my plans for implementing transactions with a colleague at
GitLab, Sami Hiltunen, he pointed out an optimization: by keeping track of
the current index at the beginning of the logical transaction, we could skip
verifications for which no subsequent log entry impacted. This lets us do
fewer duplicate read operations at the expense of some additional bookkeeping,
to track entries newer than the oldest transaction and which paths they
modified in storage.

However, while this speeds up the batch application's view, it doesn't help us
avoid unnecessarily committing the verifications to the log itself, as we do
this verification within the batch application. Better, though significantly
more work, would be to do a pre-application sanity check, allowing us to drop
unnecessary verification operations from our commit if we could tell at
[request time][raft-apply-log] that further verification was unnecessary.

This is left as a future improvement.

Additionally, we are currently sub-optimally using [caches][physical-cache]
in transactions. Because we do not have a transaction-aware cache library,
we currently create a new, empty cache per transaction and do not repopulate
the global cache on successful commit to the underlying storage. This limits
our performance on high-latency storage backends which support transactions.
However, fixing this likely requires expensive locking: all write, transaction
creation and commit events likely require an exclusive lock to ensure
consistency of the cache. A more transaction aware cache implementation would
also be beneficial, so that we are not duplicating the entire cache at
transaction creation time; perhaps the existing [memdb library][memdb] could
be used for this.

This is also left as a future improvement.

:::info
We'd love feedback and testing on the transactional storage implementation!

Build OpenBao from the `main` branch and submit any bug reports or
performance discrepancies via [GitHub issue][file-issue].
:::

[raft-algo]: https://raft.github.io/
[etcd]: https://etcd.io/
[WAL]: https://en.wikipedia.org/wiki/Write-ahead_logging
[raft-backend]: https://github.com/openbao/openbao/tree/main/physical/raft
[hcp-raft]: https://github.com/hashicorp/raft
[raft-fsm]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/fsm.go
[storage-write]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/raft.go#L1523-L1553
[storage-read]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/raft.go#L1493-L1521
[transaction-rfc]: https://openbao.org/docs/rfcs/transactions/
[bbolt-txn]: https://pkg.go.dev/go.etcd.io/bbolt#Tx
[bbolt-txn-limits]: https://pkg.go.dev/go.etcd.io/bbolt#pkg-overview
[txn-commit]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/transaction.go#L610-L722
[hash-value]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/transaction.go#L97-L115
[list-impl]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/transaction.go#L479-L485
[txn-apply]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/fsm.go#L678-L758
[batch-apply-txn]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/fsm.go#L824-L838
[raft-apply-log]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/physical/raft/raft.go#L1598-L1689
[physical-cache]: https://github.com/openbao/openbao/blob/c9201295ed833b431249f4592f32b1946b69f263/sdk/physical/cache.go
[memdb]: https://pkg.go.dev/github.com/hashicorp/go-memdb
[file-issue]: https://github.com/openbao/openbao/issues/new?assignees=&labels=bug%2Cpending-decision&projects=&template=bug_report.md&title=
