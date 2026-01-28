---
title: Improved Horizontal Scalability
description: 'With the 2.5.0 release OpenBao enables standby nodes to serve read-request, a first step towards better Horizontal Scalability.'
slug: improved-horizontal-scalability
authors: phil9909
tags: [announcement, technical, performance]
image: https://raw.githubusercontent.com/openbao/artwork/refs/heads/main/color/openbao-vertical-text-color.svg
---

## Summary

In this blogpost, I will give you an overview of the new Horizontal Scalability
feature of OpenBao, its (current) limitations and planned future developments.
In the second part, I will show some benchmarks to see in which cases the new
feature helps (spoiler: it works best in read-heavy workloads, but doesn't
improve write-heavy workloads).

<!-- truncate -->

## Recap on Scalability Terminology

Let's quickly recap what "horizontal" means in the context of scalability: To
scale a service up (i.e. allow it to handle more load) there are two options:
Give each instance more resources (CPU, memory, network speed, disk capacity,
...) or increase the number of instances. Increasing instance size is referred
to as "vertical" and increasing the number of instances is referred to as
"horizontal" scaling.

Whether this is successful, depends on the problem at hand and the
implementation. There are some problems that scale very well - both horizontally
and vertically - like serving static files. Given that the server is implemented
reasonably well, either doubling the resources per instance or doubling the
number of instances should both double the number of static files you can serve.
Once you start to introduce mutability scalability starts to suffer, especially
if you want to provide strong consistency guarantees.

## Recently released Horizontal Scalability Features

With the OpenBao release 2.5.0, we introduced what we call "read scalability".
To ensure High Availability, OpenBao supported "standby nodes" since we forked
from Vault. One of these nodes would automatically take over active duty, if the
current leader nodes goes down (planned or unplanned). We extended this feature
to allow the "standby nodes" to become "read-only nodes", meaning they can now
serve read requests on their own, while write requests are still forwarded to
the leader.

This has some limits:

- The obvious being: If you have mostly write requests with only a few
  read-only requests, then read scalability won't help.

  :::info
  Keep in mind that a read request on the API level might still require a write
  to the storage, e.g. [reading a dynamic secret from the database
  plugin][dynamic-secrets] will require a write to storage, because after its
  TTL has expired, it needs to be deleted and for this OpenBao has to do
  "bookkeeping".
  :::

- Currently, only the Raft storage backend is supported. Support for PostgreSQL
  is in the works.

There are also some caveats:

- It might require changes to your load-balancer setup: If no traffic is routed
  to the "read-only nodes", then they won't remove any load from the primary.

- Data read from a standby node might be stale, if it has recently been updated
  on the primary. If this is unacceptable to you in general, you can set
  [`disable_standby_reads = true` in your configuration][disable_standby_reads]
  to disable reads from standby. Or, if this is acceptable most of the time, you
  can ensure to read from the primary in cases where you need the latest data.

## Horizontal Scalability Outlook

Consistent writing in a distributed fashion is an inherently hard problem. If we
were set out to solve this in a general purpose way, we'd be doomed to fail. We
need to look out for properties of our specific case, that we can exploit:
Currently, there is one leader node per cluster, which will handle all write
request. We are planning to change this and have leader nodes per namespace,
which will handle all write requests for their namespace. As write requests
between sibling namespaces are independent, there is no risk of violating data
integrity (a property we can exploit :tada:).

This again has an obvious limitation: if you do not use namespaces or if most of
your traffic is within a single namespace (e.g. you have a test and prod
namespace and prod accounts for 99% of the load) this won't help. But let's take
one step at a time and maybe it is even good enough, because you are either
small enough to have no scalability problems or big enough to use namespaces
anyway.

Now it is time to look at some benchmarks.

## Benchmarks

### Setup

I have set-up two 3-node OpenBao clusters on Azure, one running OpenBao 2.4.4
and one running OpenBao 2.5.1. Each cluster has a dedicated load balancer, but
the load balancer for 2.4.4 is configured to direct traffic only to the primary
node and the load balancer for the 2.5.1 cluster will distribute the traffic
among all nodes.

I ran two benchmarks, one for the KV engine and one for the PKI engine. Both of
them for 5 minutes per cluster using the [`benchmark-openbao`][] tool.

### KV Engine Benchmark

The benchmark aims for 500 requests per second, with 90% reads and 10% writes.

<details>
    <summary>Full `benchmark-openbao` Config</summary>

```hcl title="benchmark_kv.hcl"
duration = "5m"
cleanup  = true
workers = 2000
rps = 500

disable_keep_alive = true

test "kvv1_write" "writes" {
  weight = 10
  config {
    numkvs = 10
    kvsize = 100
  }
}

test "kvv1_read" "reads" {
  weight = 90
  config {
    numkvs = 10
    kvsize = 100
  }
}
```

</details>

If we take a look at the per-node CPU usage, we can clearly see the effects. The
first plot shows the CPU usage of the 2.4.4 cluster over a 15 minute timespan
(average per minute) with the 5 minute benchmark roughly centered. Before and
after the benchmark, we can see the active node hovering around 4% CPU usage,
while the standbys use around 2%. During the benchmark it raises to around 60%
for the primary and 8% for the standbys.

![CPU usage of 2.4.4 during the benchmark run](/img/2026-03-25-improved-horizontal-scalability/benchmark-kv-2-4-4.svg)

The next plot shows the same data for the 2.5.1 cluster. In the first plot
we could clearly see which line is the primary, but here all lines are very
similar. Before and after the benchmark the CPU usage hovers around 4% jumping
up to 30 to 35% for all nodes during the benchmark.

![CPU usage of 2.5.1 during the benchmark run](/img/2026-03-25-improved-horizontal-scalability/benchmark-kv-2-5-1.svg)

This results in better latencies (2.4.4 has a small advantage on the read
latencies, but 2.5.1 is much better for write):

<!--
op      count   rate        throughput  mean         95th%        99th%         successRatio
reads   134985  449.962167  449.940453  3.911434ms   14.155784ms  24.966551ms   100.00%
writes  15015   50.052706   50.048404   44.556346ms  79.047098ms  110.033005ms  100.00%

op      count   rate        throughput  mean         95th%        99th%         successRatio
reads   135034  450.126267  450.120993  3.714888ms   12.54901ms   22.407885ms   100.00%
writes  14966   49.899488   49.895550   68.364191ms  86.199986ms  1.428659151s  100.00%
-->

| operation | version | mean     | 95th%     | 99th%      | count  |
|-----------|--------:|---------:|----------:|-----------:|-------:|
| reads     | 2.5.1   |  3.91 ms | 14.16 ms  |   24.97 ms | 134985 |
|           | 2.4.4   |  3.71 ms | 12.55 ms  |   22.41 ms | 135034 |
| writes    | 2.5.1   | 44.56 ms | 79.05 ms  |  110.03 ms | 15015  |
|           | 2.4.4   | 68.36 ms | 86.20 ms  | 1428.66 ms | 14966  |


### PKI Engine Benchmark

The benchmarks aims for only 5 requests per second, generating RSA 2048
certificates with [`no_store = true`][no_store], which makes this a read-only
operation. Generating a (RSA) private key is quite heavy on the CPU, therefore
the low number of requests.

<details>
    <summary>Full `benchmark-openbao` Config</summary>

```hcl title="benchmark_pki_rsa2048_no_store.hcl"
duration = "5m"
cleanup  = true
workers = 15
rps = 5

disable_keep_alive = true

test "pki_issue" "pki_issue" {
    weight = 100
    config {
        setup_delay="2s"
        root_ca {
            common_name = "benchmark.test Root Authority"
            key_type = "rsa"
            key_bits = "2048"
        }
        intermediate_csr {
            common_name = "benchmark.test Intermediate Authority"
            key_type = "rsa"
            key_bits = "2048"
        }
        role {
            ttl = "10s"
            no_store = true
            generate_lease = false
            key_type = "rsa"
            key_bits = "2048"
        }
    }
}
```

</details>

:::tip[Performance Tip]
If you are using the PKI engine and issue a fair amount of certificates, you
should consider [using Certificate Signing Requests (CSRs)][use-csr] instead of
generating the private key on the OpenBao cluster. Also, using ECDSA or Ed25519
instead of RSA where possible will improve the performance, see "[Key types
matter][]"
:::



Here again we have two graphs, first from the 2.4.4 cluster followed by the
2.5.1 cluster. During idle the results are the same as before.

On 2.4.4 cluster the primary spikes to 100% CPU usage, while the standbys don't
see any change (because in contrast to the KV benchmark there are no writes
happening, so they have no raft updates to apply).

![CPU usage of 2.4.4 during the benchmark run](/img/2026-03-25-improved-horizontal-scalability/benchmark-pki-2-4-4.svg)

On the 2.5.1 cluster the load is spread pretty well at roughly 40%.

![CPU usage of 2.5.1 during the benchmark run](/img/2026-03-25-improved-horizontal-scalability/benchmark-pki-2-5-1.svg)

This time we also see better latencies, but additionally the 2.4.4 cluster
failed to even fulfill the 5 requests per second target and two requests (0.43%)
even failed.

<!--
op         count  rate      throughput  mean          95th%         99th%         successRatio
pki_issue  1500   5.003329  4.996498    278.749266ms  724.061639ms  1.080919148s  100.00%

op         count  rate      throughput  mean          95th%          99th%          successRatio
pki_issue  467    1.553848  1.497935    9.752393603s  22.089775925s  35.697547865s  99.57%
-->

| version | count  | mean       | 95th%       |  99th%       | rate  | success |
|--------:|-------:|-----------:|------------:|-------------:|------:|--------:|
| 2.5.1   | 1500   |  278.75 ms |   724.06 ms |   1080.92 ms | 5.00  | 100.00% |
| 2.4.4   | 467    | 9752.39 ms | 22089.78 ms |  35697.55 ms | 1.55  |  99.57% |

### Missing Benchmarks

I decided against showing a write heavy benchmark, like PKI with `no_store =
false` or KV with 100% write. Not because I want to hide the fact that our read
scalability feature does not help here, but because it would be boring to look
at. The results for both version would be similar, the only thing you could see
is that for 2.5.1 the standby nodes use a little more CPU while the cluster is
idle (as we have seen before).

[disable_standby_reads]: /docs/next/configuration/
[dynamic-secrets]: /docs/secrets/databases/#usage
[Key types matter]: /docs/secrets/pki/considerations/#key-types-matter
[no_store]: /api-docs/secret/pki/#create-update-role
[use-csr]: /api-docs/secret/pki/#sign-certificate
[`benchmark-openbao`]: https://github.com/openbao/benchmark-openbao
