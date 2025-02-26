---
title: "Vision for Namespaces, Horizontal Scalability"
description: "Description of Alex's vision for how Namespaces and Horizontal Scalability can improve OpenBao"
slug: vision-for-namespaces
authors: cipherboy
tags: [vision, community, technical]
---

As the OpenBao community [starts development on Namespaces](https://github.com/openbao/openbao/issues/787)
and the Horizontal Scalability Working Group has its kickoff, I wanted to take
the opportunity to put forward a blog post describing how these two groups'
work can compliment each other and provide an alternative path forward other
than Vault Enterprise's Performance Secondary and Disaster Recovery clustering
modes.

<!-- truncate -->

## Scaling Read Operations

Most obviously, the first step for the Horizontal Scalability working group
will be to [allow standby nodes to service requests](https://github.com/openbao/openbao/issues/569)
as described in our project direction & roadmap:

> 4. Allow HA standby nodes to service read-only (from a storage modification PoV) requests. (scalability)
>    - Currently HA mode standby nodes forward all requests up to the active node, preventing horizontal scalability of OpenBao. Due to limitations in Raft (only the active node can perform storage writes), we can't immediately scale writes. Thus, start by bringing these nodes "online" (loading the mount table, plugins, &c) and allowing them to service read-only requests, returning `ErrReadOnly` on storage write operations to trigger automatic request forwarding.

The shortcoming of this is that writes are not scalable: there is still only
a single active writer node. Note that a read operation in this context refers
to any API request (of any operation type) that results only in `get` or `list`
("read") storage operations. Any operations involving a storage write (`put`
or `delete`) would be forwarded to the active node for processing.

This behaves similarly to Performance Secondary Standby nodes.

## Scaling Write Operations

In our RFC for namespaces, there is the following future work item:

> ### Per-Namespace Storage Segments
>
> At the physical storage level, a namespace could be implemented as a new database schema in PostgreSQL (with each plugin being a new database table) or a new disk directory in Raft/BoltDB. This can likely build on top of storage views, using the existing JSON namespace data to translate source path to destination. This would help with scaling OpenBao: each tenant would have its own data storage location and so could impact other tenants less. Theoretically this could even lead to per-segment unique storage backend depending on workload characteristics assuming no cross-segment consistency is required.
>
> However, this work is strictly disjoint from implementing namespaces as a feature and so will be done later.

In conjunction with additional changes to horizontal scalability, this change
could allow each namespace to have a different active node dictated by its
storage backend, distributing writes across the cluster. Notably, very few
operations are truly cross-namespace; this is mostly limited to the creation
and deletion of namespaces and mount move operations, which affects the
namespace store in the parent context in addition to the actual target
namespace.

The benefit of this approach is that it doesn't affect plugins, token stores,
ACL stores, or any other namespace-specific functionality. This is because
our namespace design opted to place all namespace-specific data within the
namespace's path (`/namespaces/<uuid>`) rather than mixing it within the
root of storage (`/core` or `/sys`) across all namespaces.

Additionally, this gives a natural place for segmenting storage, allowing
smaller databases when used with PostgreSQL or Raft. This allows greater
scalability as many have scalability problems when lots of data is written
to a single backend instance. By supporting different storage types (e.g.,
mixing and matching PostgreSQL and Raft), namespaces with different SLAs
or workload write/read ratios can be supported.

One shortcoming with this approach is it doesn't allow scaling all types of
workloads. For instance, a single PKI mount which stores certificates will
not be horizontally scalable as writes will not be able to be distributed.
However, the majority of large, diverse workloads will be able to be
distributed because of this change.

Another shortcoming is the complexity this entails for an operator. Some
of this may be mitigated by allowing namespace-native configuration, without
requiring full configuration file changes.

## Disaster Recovery

OpenBao recently added support for [Raft non-voter nodes](https://github.com/openbao/openbao/issues/578).
This can likely form the basis of [disaster recovery](https://github.com/openbao/openbao/issues/38),
especially if enablement for other storage backends (like PostgreSQL) is
added.

Notably in Raft, non-voter status means that these nodes do not contribute to
quorum requirements, allowing writes to commit faster but still allowing the
use of Raft to distribute updates. This means that adding non-voter nodes
results in additional traffic from the leader but doesn't otherwise impact
write speeds. By putting these non-voters in secondary data centers, with
[the ability to promote non-voter nodes](https://github.com/openbao/openbao/pull/996),
we can subsequently initiate a failover operation in the event the primary
cluster goes down, with minimal data loss.

PostgreSQL can similarly be extended to support a non-voter setup, wherein
certain nodes will not attempt to become leaders unless updated later. This
will behave similarly to Raft, allowing more read scalability via the use of
read-only PostgreSQL replicas in other secondary data centers.

By broadening [the use of transactions](https://github.com/openbao/openbao/issues/607),
we can further guarantee that these other nodes are consistent, independent
of what storage backend is used.

Additionally, we could allow standby or non-voter nodes to serve read requests
without an active leader. This could potentially be extended to support
generating offline authentication tokens using JWTs or similar signature-based
schemes for use with non-lease paths. This would allow for greater high
availability in the event of a leadership outage.

## Offline Recovery Mode

Sometimes a hybrid replication mode would be preferred; Vault Enterprise
supports this via a [path filtering operation](https://developer.hashicorp.com/vault/api-docs/system/replication/replication-performance#create-paths-filter).

When we combine the [earlier work for per-namespace storage backends](#scaling-write-operations)
with an additional Namespaces future work item:

> ### Per-Namespace Seal Mechanisms
>
> The existing Vault Enterprise Namespace feature supports locking and unlocking namespaces by an operator with access to the parent namespace. While potentially useful to limit requests to a namespace without impacting other users, we could add a similar mechanism using the Barrier + Keyring functionality to also give us per-tenant encryption. This also lets the tenant control their own encryption keys. With lazy loading of namespaces (preventing inbound requests unless the namespace is unsealed), this behaves similarly to locking and unlocking the namespace though doesn’t conflict with it.
>
> However, this work is strictly disjoint from implementing namespaces as a feature and so will be done later.

If we implement non-hierarchical namespaces, which do not chaining to `root`
as a parent for tokens, ACL policies, or layered sealing, this allows us to
have cluster-independent namespaces. We would additionally need the Shamir
fallback [from the parallel unseal RFCs](https://github.com/openbao/openbao/issues/1021).

This gives two nice properties:

1. We can have a stronger path filtering, allowing replication of namespaces
   in disjoint cluster topologies. For instance, a secondary site may have only
   a subset of namespaces, which it may be non-voter on until promoted to
   leader during an outage.
2. A namespace could potentially be shared by two different organizations as
   a form of secret sharing with some peer establishment protocol.

Notably, the parallel unseal allows either Shamir's based initial
establishment or the use of public keys explicitly provisioned for local-only
seal material usable by the remote cluster. This allows local disaster nodes
to survive the outage of the primary seal mechanism.

## Lazy Loading

By making Namespaces have their own seal mechanism, we'll be forcing OpenBao
to handle the scenario when a namespace cannot be loaded. We have two options:

1. To hard fail, requiring operators to rectify the problem immediately. With
   things like parallel unseal, this should be doable unless a storage engine
   itself is down.
2. To soft fail, refusing to load the namespace (and any children) but
   continuing regular operation on all other namespaces.

This sits on different sides of a security/availability problem: we could be
available, but not processing key revocations because a single namespace is
offline, or we could be in a similar place, not processing all revocations
because a single offline namespace resulted in all namespaces being
unavailable.

I'd like to see namespaces, and eventually mounts, be lazily loadable. This
will likely require new interfaces for backends to indicate when they'd next
like their Rollback function to be issued, if that occurs too infrequently.
And mounts will need to be audited for lease expiry, with some window for
mount reuse without unmounting refreshed on last request.

But, this will allow us to scale OpenBao to workloads with lots of
infrequently-accessed mounts without requiring all nodes in a cluster have
the capability of loading the entire system at once.
