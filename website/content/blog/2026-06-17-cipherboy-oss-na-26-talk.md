---
title: "OpenBao: Horizontally Scaling Secrets Management - OSSNA 2026"
description: "Blog of Alex's talk at Open Source Summit North America 2026, describing the horizontal scalability features of OpenBao."
slug: cipherboy-ossna-26-talk
authors: cipherboy
tags: [community, conferences, talks]
---

Slides and content from Alex's Open Source Summit NA 2026 talk, describing the horizontal scalability features of OpenBao.

For a video, see the Linux Foundation's [official YouTube channel](https://www.youtube.com/watch?v=vNsEAmNPwH0).

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-01.svg">
SVG rendering is not supported on your browser.
</object>

Welcome everyone to my talk on OpenBao and how we added horizontal scalability to the project. I'm Alex Scheel, Head of OpenBao Development at ControlPlane, a long time member of the OpenBao TSC, and chair of the OpenBao Development Working Group.

I've been fortunate to have a hand in the development of OpenBao since nearly the beginning of the project, and before that, at HashiCorp's Vault CryptoSec team.

If, like me, you were wishing you could get out for a post-lunch walk, thank you for staying, but we'll have to settle for some photos of Minneapolis I've sprinkled through the presentation. And thank you all for visiting Minnesota, whether from near or far!

<!-- truncate -->

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-02.svg">
SVG rendering is not supported on your browser.
</object>

First, what is OpenBao?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-03.svg">
SVG rendering is not supported on your browser.
</object>

OpenBao is an open-source secrets manager, featuring everything from static and dynamic secrets to PKI and key management services. We have integrations with everything from External Secrets Operator and Cert Manager to OpenTofu, SOPS, and cosign.

We also have a growing ecosystem; check out our ecosystem page afterwards and if you're an adopter, integrator, or supporter, consider adding your logo!

OpenBao is an OpenSSF Sandbox project and is licensed under the MPLv2.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-04.svg">
SVG rendering is not supported on your browser.
</object>

If this sounds familiar, it should be!

OpenBao is the open-source continuation of HashiCorp Vault, started in late 2023 after the relicensing to the non-OSI BUSL license.

We aim to keep API compatibility for client applications, but to improve the operator and developer experience. Towards that goal, we've landed several Vault Enterprise features--such as horizontal scalability, which this talk focuses on--but also many original improvements like declarative self-initialization, storage-level improvements for better performance and snapshot consistency, and landing in our next release, things like an externally pluggable KMS interface, operator-defined workflows built on the existing profile engine, and per-namespace (per-tenant) barrier encryption keys with optional namespace sealing support.

(This photo is taken from the Mill Ruins park, facing the Mill City Museum which is hosting tonight's drone show.)

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-05.svg">
SVG rendering is not supported on your browser.
</object>

OpenBao's top-level governance body, its technical steering committee (TSC), is currently made up of the following companies: my employer, ControlPlane, a seat jointly occupied by SAP and Liquid Reply who SAP has contracted with to contribute to our community, Adfinis, Wallix, IOTech, and GitLab.

Our governance is openly documented in the project’s main repository. We have tracks for leadership (in the form of the TSC), for developers (in the form of the Dev Working Group and its many sub-working groups), and maintainership for those interested in contributing to reviews on the project. We’ve also started a marketing working group if talking about OpenBao or its usage is more your style.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-06.svg">
SVG rendering is not supported on your browser.
</object>

In my early 2025 talk at FOSDEM (which you can see on the OpenBao blog archive), I mentioned that I had hoped to grow a community around OpenBao of companies that make money supporting it, just like Kubernetes. Not long after that talk, both Adfinis and SAP stepped up and started contributing to the community. This March, I joined ControlPlane to further that mission as well, leading our efforts to commercialize support and maintenance of the project. You can read more about that on ControlPlane's blog.

ControlPlane employs maintainers for FluxCD, is a contributor to several CNCF and OpenSSF efforts, and focuses on a highly regulated customer base like banks and government entities.

I'm happy to report for anyone following along, the OpenBao community is healthy, growing, and my hopes have been answered! Though of course, we always welcome more contributions of any sort!

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-07.svg">
SVG rendering is not supported on your browser.
</object>

This now brings us to what we're here to discuss. Horizontal Scalability, and the journey to support it.

I'll focus on three parts mostly:

1. What building blocks did the fork have? What were we starting with?

2. How did we support Raft in OpenBao v2.5.0? What challenges did we face along the way?

3. How will we support PostgreSQL and more going forward? How will this improve the operator experience?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-08.svg">
SVG rendering is not supported on your browser.
</object>

We started by trying to understand what we inherited from HashiCorp Vault.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-09.svg">
SVG rendering is not supported on your browser.
</object>

Most importantly, we started with a highly available (though, not horizontally scalable!) base. In OpenBao as it stood before this feature, we had data replication already taken care of. We supported two HA storage backends (Integrated Storage aka Raft and PostgreSQL),

OpenBao and HashiCorp Vault have a single active node which can perform write operations; this is a limitation of the Raft protocol and used as a design decision elsewhere.

In Vault Community Edition which we inherited, probably for open-core feature differentiation with Vault Enterprise, HashiCorp only supported cold standbys: these were "unsealed" and ready to take over if the active node went down, but could only forward requests to it and did not do any processing locally.

In OpenBao v2.5.0, we wanted to land horizontal scalability, which meant we needed a way for these cold standby nodes to serve read requests. They still wouldn't handle write requests, but they could help alleviate some of the load from the single active node, depending on the user's workloads.

And, of course, we had a constraint that we wanted to behave similarly to Vault Enterprise's Performance Standby node types.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-10.svg">
SVG rendering is not supported on your browser.
</object>

How does Vault Enterprise behave? And what is a read request?

Vault Enterprise roughly defines a read request as something that doesn't cause any storage writes.

Confusingly, this has a very loose association with HTTP verbs. For instance, the Certificate Revocation List (CRL) rotation endpoint in the PKI engine incurs a storage write (the CRL itself), but uses the GET verb. More obviously, login, e.g., via the `userpass` authentication method, causes several storage writes.

Both of these, if they come into a read-enabled standby, would be forwarded.

For the types of requests that will be handled by a standby node, a KVv1 secret read operation would be handled locally; it is guaranteed to not have any write operations. Most KVv2 operations will not have any writes either. Additionally, some POST operations will be strictly handled locally: if a PKI engine's role is configured not to store leaf certificates, the issuance endpoint could be handled on the read-enabled standby node.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-11.svg">
SVG rendering is not supported on your browser.
</object>

From an operational standpoint it is now clear what we want to achieve, though we have a few quirks we need to work out with our storage backends. How do we handle invalidation of caching that occurs naturally?

For integrated storage, each OpenBao node becomes its own storage backend. It uses the Raft consensus protocol to handle replication of data between all nodes. This protocol is based on a leadership election process, which requires an odd number of voting nodes to be consistent. Each write sent by the leader is confirmed by another vote.

This write confirmation forms the basis of the write-ahead-log (WAL) mechanism. This WAL mechanism contains enough information about every storage write, which gives us an easy way to invalidate cached storage entries.

On PostgreSQL however, any number of nodes can be used as they all race to acquire a lock stored in the database. While PostgreSQL handles the data replication for us--giving us a M:N OpenBao service to database node decoupling--it doesn't by default provide enough information for invalidation on standby nodes. But more on that later.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-12.svg">
SVG rendering is not supported on your browser.
</object>

Looking at the existing code base, there's a few hints we have on how invalidation is supposed to work.

This is a snippet of code from the PKI secrets engine. There are two parts I bolded:

1. When we invalidate, we're given a context and the path of the storage entry that changed. We don't get the contents of the entry or if it was updated or deleted.
2. Similarly, we see that we shouldn't block too long: this code path spins off a goroutine to handle the update in the background. Other code paths in this function just flip the value of an atomic boolean for the next API request to adjust.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-13.svg">
SVG rendering is not supported on your browser.
</object>

Putting this together, we learned that cache invalidation must be definite, operating on specific keys which were invalidated; it isn't TTL based. There must be some storage-path-based routing engine that dispatches invalidations from the storage layer, through core, to the plugin.

And, because invalidation must be in some hot path (in the case of Raft, we know it must be part of the WAL application process), we've learned that handling the invalidation synchronously isn't good for performance, so we should execute it asynchronously.

(This photo is features the Third Avenue bridge, looking back on downtown Minneapolis.)

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-14.svg">
SVG rendering is not supported on your browser.
</object>

Moving right along, it was time to implement this.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-15.svg">
SVG rendering is not supported on your browser.
</object>

The design idea roughly looked something like this:

1. We started by assuming we could just load all core subsystems and plugins on the standby node.
2. We allowed requests to come in, rather than automatically forwarding them. After this, we built a mechanism to conditionally forward requests when a storage write occurred.
3. And we built a cache invalidation layer based on the earlier analysis of our existing code, and a mechanism for routing storage paths to the owning subsystem.

Simple, right?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-16.svg">
SVG rendering is not supported on your browser.
</object>

Starting from the existing HA code, it took a lot of work to refactor core to (correctly!) bring up the standby node as a reader. While conceptually simple, we found that we had some partial state (from being non-read-enabled) that we need to make sure we reset. And we found we needed a new post-unseal strategy which did not incur any writes and didn't load any subsystems which only performed writes, such as automatic barrier key rotation or starting the request forwarding server (which standbys connect to).

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-17.svg">
SVG rendering is not supported on your browser.
</object>

When processing read requests, we changed the request routing to now only conditionally forward the request (if the node was still a cold standby), and default to processing requests. This necessitated a second forward pass if the request could not be handled locally. Notably, a failed write request would result in no state, as the standby nodes cannot write to their underlying storage.

In creating this, we needed to refactor how requests were processed at the http layer: previously we only read the body once, either to forward it or to process it on the active node. However, as we now consumed the body twice, we built a way of spooling the request body and resetting back to the initial state on forward.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-18.svg">
SVG rendering is not supported on your browser.
</object>

The contract between OpenBao's core and its storage engines is conceptually simple: the storage engine just needs to tell us when a write occurs, so we can define a callback approach for this in the base `sdk/physical` interface.

This was implemented in the Integrated Storage (Raft) backend.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-19.svg">
SVG rendering is not supported on your browser.
</object>

However, the actual dispatch of invalidations is more complex.

We take pending callbacks from the storage engine and queue them into an asynchronous fairshare job queue, sharded by expected namespace. This prevents one particularly noisy tenant from starving all other tenants, at the cost of not necessarily guaranteeing relative order of writes across namespaces.

This job then handles the storage-level routing of written path to owning backend. Some backends are privileged, like the core of OpenBao itself, and can take longer to process invalidations. For instance, the mount table explicitly reloads the new entry, potentially spinning off a new external plugin process so that it is ready before the next inbound request. Requests routed to an sandboxed plugin, e.g., PKI, get processed with a short, 2 second context to enforce strict asynchronous behaviors and use of their own background worker contexts.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-20.svg">
SVG rendering is not supported on your browser.
</object>

The result of all this is that standby nodes now process read requests. In the chart on the left, before adding read request handling, only a single service process was consuming CPU. Now, on the right, all three service processes share this developer's machine and consume CPU processing requests.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-21.svg">
SVG rendering is not supported on your browser.
</object>

When it comes to running in a real, multi-node deployment, the impact becomes more clear. Where there was more contention for certain locks, the OpenBao v2.4.4 cluster's single active node was able to handle far fewer PKI certificate issuance operations. The other two standbys were completely idle.

In OpenBao v2.5.1, all three nodes were able to service requests, decreasing lock contention, giving us higher throughput and lower latency.

You can read more about this in Philipp's entry on the OpenBao blog.


Of course, things don't always go as planned. For some example of bugs we've fixed:

1. When loading current state, we didn't pass through standby vs active node status to all places that needed it. This meant that, when upgrading a legacy non-transactional storage type to a read-enabled standby (say, in a direct migration from OpenBao v2.0.0 to v2.5.0), we'd fail to start up.

2. Certain types of specially handled requests (like root token generation) were not correctly forwarded to the active node as they were outside the regular request routing mechanism. This will be fixed in 2.5.4 coming this week.

3. But most of our bugs have been in the largest section of new code: invalidation routing. While plugin's invalidation logic was already present in Vault Community Edition, most of the core invalidation logic was presumably hidden in Vault Enterprise and wasn't part of our code base. This is the most difficult to test as it requires understanding and validating each individual subsystem.

Mostly these come from community bug reports -- and some patches have even come from drive-by contributors, which is always appreciated.


The release series containing horizontal read scalability, OpenBao 2.5.x, was shipped at the start of the year, and so may already be running on your systems!

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-22.svg">
SVG rendering is not supported on your browser.
</object>

Before we move on, I'd like to thank again the contributors to this feature: Fatima was the 2025 OpenBao Mentee sponsored by Adfinis, Philipp, an Adfinis employee, was her mentor and also contributed to the design and implementation, and I helped with implementation, reviews, and debugging.

(This photo was taken by my wife, Katherine Mayo, one winter, looking from the iconic Stone Arch bridge back on the city.)

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-23.svg">
SVG rendering is not supported on your browser.
</object>

You might be thinking... wait! ... you mentioned that the invalidation hook was implemented in the Raft backend, but what happened to the PostgreSQL backend?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-24.svg">
SVG rendering is not supported on your browser.
</object>

Well, it turns out it is slightly more complicated to implement.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-25.svg">
SVG rendering is not supported on your browser.
</object>

We started by thinking that maybe the built-in `LISTEN`+`NOTIFY` support in PostgreSQL would allow a sort of storage-level inter-process communication (IPC) which would save us from implementing it at the node-level.

Among other challenges, it turns out that these events may be silently dropped if OpenBao disconnects and reconnects through a proxy such as `pgbouncer`. This makes it unreliable for our use in invalidations.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-26.svg">
SVG rendering is not supported on your browser.
</object>

PostgreSQL has a WAL as well; why can't we use it? For starters, database operators would need to configure PostgreSQL to have a higher WAL verbosity level (`wal_level=logical`). Additionally, OpenBao cannot subscribe to the WAL on read-replica PostgreSQL nodes; only the PostgreSQL primary sends WAL events. This means having two database connections rather than just one on standby nodes.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-27.svg">
SVG rendering is not supported on your browser.
</object>

We thought about adding either a last modification time to the existing OpenBao schema, which loses the ability to easily detect deletes, or adding a new WAL subscription table. The latter puts garbage collection pressure on the database and has some of the same peer longevity problems as the PostgreSQL WAL implementation. We'd need to manually remove processed invalidations and keep track of which invalidations were seen by which live standby nodes.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-28.svg">
SVG rendering is not supported on your browser.
</object>

What about moving to a more standard TTL-based expiration? The biggest issues here are that OpenBao relies on invalidating lists--that is, knowing when a new entry was created--and that invalidating certain entries, such as the mount table, is rather expensive as it holds a few global locks that block incoming requests. This means more refactoring would be needed before we could adopt this approach.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-29.svg">
SVG rendering is not supported on your browser.
</object>

Ultimately, we settled on implementing a GRPC stream-based notification mechanism, using our existing GRPC connection for forwarding requests. The standby will subscribe to the leader for invalidations, wait for the initial index to ensure it is caught up, and then begin processing both read requests and invalidations from the active. The active will send the expected index at which the data was written, which the secondary can then wait for.

Right now, OpenBao will have to manually wait for this event, but PostgreSQL 19 will introduce a `WAIT FOR LSN` operation.

The benefits of this is that OpenBao will strictly follow PostgreSQL’s lead: operators will promote or demote PostgreSQL nodes to primary, allowing writes to occur, and whichever OpenBao nodes are connected to it will then self-select to become active. No OpenBao specific failover is necessary.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-30.svg">
SVG rendering is not supported on your browser.
</object>

The good news is that this approach will hopefully scale to any indexed replicated storage backend, and open up new opportunities in the future.

This is under active development and should be in OpenBao v2.7.0.

(This photo showcases Target Field, where the Minnesota Twins play -- I hear the Linux Foundation has been organizing some visits to watch them play this week.)

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-31.svg">
SVG rendering is not supported on your browser.
</object>

Briefly before we wrap up, a few more things to mention:

1. We're introducing stronger consistency semantics for clients through index headers, aligning with and extending Vault Enterprise's implementation here. This should hopefully help clients to see fewer stale reads.
2. We also have a roadmap towards write scalability through per-namespace storage backends.

In Vault Enterprise, this looks like the performance secondary cluster architecture, allowing a very limited form of write scalability: mounts (regardless of namespace) can be mounted as cluster-local, essentially creating a forked/hybrid cluster. Plugin authors can also opt-in to write certain paths to cluster-local storage, such as the PKI plugin’s leaf certificates. This has caused problems for plugins whose clients expect global knowledge: PKI’s CRL functionality needed special cross-cluster synchronization support.

OpenBao is thinking about this in a different way: by using namespaces as the isolating boundary, we know very few storage operations will cross the namespace boundary. This will form the basis for our envisioned multi-writer support: first we’ll add lightweight storage separation (different tables at the BBolt and PostgreSQL levels) using the same storage backend, allowing things like namespace-level storage quotas. Then we’ll introduce out-of-hierarchy namespaces, defined in the configuration file. These won’t inherit policies and access from the root namespace, behaving more like a lightweight, fully-isolated core. Lastly, we’ll move to separate storage backends altogether, adding in the ability for namespaces to designate themselves as active (versus a single global active node). This will allow write scalability across namespaces.

Ultimately, we hope this will lead to a different set of operator tradeoffs: the simplicity of a flat cluster (versus a treed hierarchy) should be easier for operators to understand and we’ll have better write scalability across an entire cluster rather than on a more adhoc basis.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-32.svg">
SVG rendering is not supported on your browser.
</object>

Lastly, if you're interested in getting involved with the project, check out our community calendar on Proton! You can contribute to a development direction item, join a working group, like our posts on social media, add your logo to the OpenBao Ecosystem page, or just start using OpenBao for your secrets management needs.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-ossna-26/Horizontal-Scalability-Slide-33.svg">
SVG rendering is not supported on your browser.
</object>

Thank you very much!

If you have any questions later or just want OpenBao stickers, feel free to come and find me at the conference. I may be at the OpenSSF booth, but if not, they--or you--should be able to contact me on their Slack instance. John from ControlPlane and a newly announced OpenSSF Ambassador is also wandering around if I'm busy!

Does anyone have questions now?
