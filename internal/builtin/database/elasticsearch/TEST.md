<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Elasticsearch Plugin — Test Plan

## Always-on unit tests

```
$ go test ./internal/builtin/database/elasticsearch/...
```

The full request flow (Initialize → NewUser → UpdateUser → DeleteUser) is
exercised against an `httptest.Server`, including the path-shape assertion
and the legacy `_xpack/security/` swap.

## Acceptance / manual

Gated on `BAO_ACC=1` + `ES_URL`. The `TestES_Acceptance` test is a marker;
the manual run book follows.

### Local Elasticsearch via Docker

```
$ docker run --rm -d --name es \
    -e xpack.security.enabled=true \
    -e xpack.security.transport.ssl.enabled=false \
    -e ELASTIC_PASSWORD=elastic \
    -e discovery.type=single-node \
    -p 9200:9200 docker.elastic.co/elasticsearch/elasticsearch:8.13.0
```

### End-to-end with `bao`

```bash
$ make elasticsearch-database-plugin
$ bao server -dev

$ bao secrets enable database
$ bao write database/config/es \
    plugin_name=elasticsearch-database-plugin \
    url=http://localhost:9200 \
    username=elastic password=elastic \
    tls_skip_verify=true \
    allowed_roles='reader'

$ bao write database/roles/reader \
    db_name=es \
    creation_statements='{"elasticsearch_roles":["superuser"]}' \
    default_ttl=1h

$ bao read database/creds/reader

# Verify:
$ curl -u <USERNAME>:<PASSWORD> http://localhost:9200/_cluster/health

# Revoke:
$ bao lease revoke <LEASE_ID>
$ curl -u <USERNAME>:<PASSWORD> http://localhost:9200/_cluster/health
# 401 Unauthorized

# Root rotation
$ bao write -force database/rotate-root/es
```

### Failure modes

| Scenario | Expected behavior |
| --- | --- |
| `creation_statements` is not JSON | Init or NewUser fails with "creation_statements must be a JSON role doc" |
| `elasticsearch_roles` missing/empty | "elasticsearch_roles is required" |
| HTTP 503 from cluster | Error propagates with response body |
| `use_old_xpack=true` | Plugin targets `/_xpack/security/user/<name>` |
| Delete on non-existent user | 404 is treated as success |
| Bad TLS chain (no tls_ca) | Init fails with TLS verify error |
| URL hostname differs from certificate SAN | Set `tls_server_name` to the certificate's DNS name; verification succeeds |
