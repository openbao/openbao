<!--
Copyright (c) AppsCode Inc.
SPDX-License-Identifier: MPL-2.0
-->

# Apache Solr Plugin — Test Plan

## Always-on unit tests

```
$ go test ./internal/builtin/database/solr/...
```

Covers Type/Version, JSON statement parsing, and a full
Initialize → NewUser → UpdateUser → DeleteUser flow against
`httptest.Server`, asserting that each Solr Security API path is hit in
the right order.

## Acceptance / manual

Gated on `BAO_ACC=1` + `SOLR_URL`. Run book follows.

### Local Solr via Docker

```
$ docker run --rm -d --name solr -p 8983:8983 \
    -e SOLR_OPTS="-Dsolr.authentication.opaque=true" solr:9
```

Enable Basic Auth by uploading a `security.json` (see Solr docs) with
the root user `solr / SolrRocks`. Then:

### End-to-end with `bao`

```bash
$ make solr-database-plugin
$ bao server -dev

$ bao secrets enable database
$ bao write database/config/solr \
    plugin_name=solr-database-plugin \
    url=http://localhost:8983/solr \
    username=solr password=SolrRocks \
    allowed_roles=reader

$ bao write database/roles/reader \
    db_name=solr \
    creation_statements='{"roles":["read-only"]}' \
    default_ttl=1h

$ bao read database/creds/reader

# Verify:
$ curl -u '<USERNAME>:<PASSWORD>' http://localhost:8983/solr/admin/info/system

# Revoke:
$ bao lease revoke <LEASE_ID>
$ curl -u '<USERNAME>:<PASSWORD>' http://localhost:8983/solr/admin/info/system
# 401

# Root rotation
$ bao write -force database/rotate-root/solr
```

### Failure modes

| Scenario | Expected behavior |
| --- | --- |
| Empty `creation_statements` | `dbutil.ErrEmptyCreationStatement` |
| Non-JSON `creation_statements` | "creation_statements must be a JSON role doc" |
| `set-user-role` returns 5xx | Plugin posts `delete-user` and returns the error |
| `url` missing `/solr` path | Ping returns the upstream 404 body |
| Insecure-only HTTPS endpoint | `tls_skip_verify=true` for dev only |
