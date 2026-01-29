---
title: Overview on Transactional Storage
description: A high-level overview on OpenBao's support for transactional storage.
slug: transactions
authors: cipherboy
tags: [technical, storage, core]
image: https://raw.githubusercontent.com/openbao/artwork/refs/heads/main/color/openbao-text-color.svg
---

Recently we merged the last of the [transactional storage](/docs/rfcs/transactions/) [pull requests](https://github.com/openbao/openbao/pull/262), including [PostgreSQL support](https://github.com/openbao/openbao/pull/608)!

<!-- truncate -->

Previously, upstream's storage model was built on [four basic operations](https://github.com/openbao/openbao/blob/2cb5d444b26cfdc79d814f9696c7f68f9c43606f/sdk/logical/storage.go#L31-L38): `Get(...)`, `Put(...)`, `List(...)`, and `Delete(...)`. Ahead of [OpenBao's initial v2.0.0 GA release](/docs/release-notes/2-0-0/), we added support for a fifth operation, [paginated list's](/docs/rfcs/paginated-lists/) `ListPage(...)`. Each of these operations were individually atomic, in that they either succeeded or erred with no change for a partial change.

However, there were no consistency guarantees across storage operations: two parallel requests coming into the same plugin could result in silently conflicting storage operations. For example, [in the PKI engine](/docs/secrets/pki/), fetching the default issuer (certificate authority) required at least the following reads:

 - [`/config/issuers`](https://github.com/openbao/openbao/blob/2cb5d444b26cfdc79d814f9696c7f68f9c43606f/builtin/logical/pki/storage.go#L1099-L1114) to resolve the value of `default`, and
 - [`/config/issuer/:id`](https://github.com/openbao/openbao/blob/2cb5d444b26cfdc79d814f9696c7f68f9c43606f/builtin/logical/pki/storage.go#L658-L678) to read the actual default issuer.

This meant that, if a second request came in deleting the issuer prior to the first request (say, to issue a leaf certificate) read the second entry, the first request would fail due to storage inconsistency. Or, [in the KVv2 engine](https://github.com/openbao/openbao/issues/482), a canceled delete request could result in broken entries.

Transactions fix this and allow a plugin to have a consistent view of storage and ensure that any write operations are appropriately conflicted or locked and fail safely even in the event of request cancelation or other failure modes.

Transactions also let us make several incremental design improvements: previously only single entries had consistency guarantees so the mount table had to fit within a single storage entry. Now, we can [split the mount table](https://github.com/openbao/openbao/issues/432) into separate entries and use transactions to have durable, safe modifications to these entries.

Implementing transactions had several design challenges: The HashiCorp Raft implementation had no native support for transactions, so we needed to figure out how to reconcile this with the underlying operation log. We opted to put all commits (with write operations) on the log, regardless of if they'd conflict, allowing all nodes to verify the consistency of the transaction. Further, PostgreSQL's internal locking [means that two transactions cannot be executed from the same thread](https://stackoverflow.com/questions/32255557/postgresql-hang-forever-on-serializable-transaction). This forced us to loosen up some of our transaction semantic testing, to ensure we remain compatible with both implementations. If you're interested in the exact details [be sure to check out the RFC](/docs/rfcs/transactions/).

Most importantly, we're excited about the possibilities that safer, more durable storage semantics bring!

:::info
The work is not yet done!

If you're interested in helping out, take a look at our [follow-up issue](https://github.com/openbao/openbao/issues/607): we'll need the community's help to ensure plugins and core safely use transactions for all relevant operations. We'd also appreciate feedback from anyone willing to run test workloads against the main branch to ensure the stability of both the Raft and PostgreSQL storage backends!
:::
