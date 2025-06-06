# OpenBao

----

**Please note**: We take OpenBao's security and our users' trust very seriously. If you believe you have found a security issue in OpenBao, _please responsibly disclose_ by contacting us at [openbao-security@lists.openssf.org](mailto:openbao-security@lists.openssf.org).

----

- [Website](https://www.openbao.org)
- [Mailing List](https://lists.openssf.org/g/openbao)
- [GitHub Discussions](https://github.com/openbao/openbao/discussions)
- [Chat Server](https://chat.lfx.linuxfoundation.org/)
  - `#openbao-announcements` ([matrix client](https://matrix.to/#/#openbao-announcements:chat.lfx.linuxfoundation.org), [home server](https://chat.lfx.linuxfoundation.org/#/room/#openbao-announcements:chat.lfx.linuxfoundation.org))
  - `#openbao-development` ([matrix client](https://matrix.to/#/#openbao-development:chat.lfx.linuxfoundation.org), [home server](https://chat.lfx.linuxfoundation.org/#/room/#openbao-development:chat.lfx.linuxfoundation.org))
  - `#openbao-general` ([matrix client](https://matrix.to/#/#openbao-general:chat.lfx.linuxfoundation.org), [home server](https://chat.lfx.linuxfoundation.org/#/room/#openbao-general:chat.lfx.linuxfoundation.org))
  - `#openbao-questions` ([matrix client](https://matrix.to/#/#openbao-questions:chat.lfx.linuxfoundation.org), [home server](https://chat.lfx.linuxfoundation.org/#/room/#openbao-questions:chat.lfx.linuxfoundation.org))
  - `#openbao-random` ([matrix client](https://matrix.to/#/#openbao-random:chat.lfx.linuxfoundation.org), [home server](https://chat.lfx.linuxfoundation.org/#/room/#openbao-random:chat.lfx.linuxfoundation.org))

<p align="center">
  <img width="300" alt="OpenBao Mascot" src="https://raw.githubusercontent.com/openbao/artwork/main/color/openbao-color.svg">
</p>

**OpenBao exists to provide a software solution to manage, store, and distribute sensitive data including secrets, certificates, and keys. The OpenBao community intends to provide this software under an OSI-approved open-source license, led by a community run under open governance principles.**

A modern system requires access to a multitude of secrets: database credentials, API keys for external services, credentials for service-oriented architecture communication, etc. Understanding who is accessing what secrets is already very difficult and platform-specific. Adding on key rolling, secure storage, and detailed audit logs is almost impossible without a custom solution. This is where OpenBao steps in.

The key features of OpenBao are:

* **Secure Secret Storage**: Arbitrary key/value secrets can be stored
  in OpenBao. OpenBao encrypts these secrets prior to writing them to persistent
  storage, so gaining access to the raw storage isn't enough to access
  your secrets. OpenBao can write to disk, [PostgreSQL](https://www.postgresql.org/),
  and more.

* **Dynamic Secrets**: OpenBao can generate secrets on-demand for some
  systems, such as AWS or SQL databases. For example, when an application
  needs to access an S3 bucket, it asks OpenBao for credentials, and OpenBao
  will generate an AWS keypair with valid permissions on demand. After
  creating these dynamic secrets, OpenBao will also automatically revoke them
  after the lease is up.

* **Data Encryption**: OpenBao can encrypt and decrypt data without storing
  it. This allows security teams to define encryption parameters and
  developers to store encrypted data in a location such as a SQL database without
  having to design their own encryption methods.

* **Leasing and Renewal**: All secrets in OpenBao have a _lease_ associated
  with them. At the end of the lease, OpenBao will automatically revoke that
  secret. Clients are able to renew leases via built-in renew APIs.

* **Revocation**: OpenBao has built-in support for secret revocation. OpenBao
  can revoke not only single secrets, but a tree of secrets, for example,
  all secrets read by a specific user, or all secrets of a particular type.
  Revocation assists in key rolling as well as locking down systems in the
  case of an intrusion.

Documentation, Getting Started, and Certification Exams
-------------------------------

<!-- Documentation is available on the [OpenBao website](https://www.openbao.org/docs/). -->

Developing OpenBao
--------------------

If you wish to work on OpenBao itself or any of its built-in systems, you'll
first need [Go](https://www.golang.org) installed on your machine.

For local dev first make sure Go is properly installed, including setting up a
[GOPATH](https://golang.org/doc/code.html#GOPATH). Ensure that `$GOPATH/bin` is in
your path as some distributions bundle the old version of build tools. Next, clone this
repository. OpenBao uses [Go Modules](https://github.com/golang/go/wiki/Modules),
so it is recommended that you clone the repository ***outside*** of the GOPATH.
You can then download any required build tools by bootstrapping your environment:

```sh
$ make bootstrap
...
```

To compile a development version of OpenBao, run `make` or `make dev`. This will
put the OpenBao binary in the `bin` and `$GOPATH/bin` folders:

```sh
$ make dev
...
$ bin/bao
...
```

To compile a development version of OpenBao with the UI, run `make static-dist dev-ui`. This will
put the OpenBao binary in the `bin` and `$GOPATH/bin` folders:

```sh
$ make static-dist dev-ui
...
$ bin/bao
...
```

To run tests, type `make test`. Note: this requires Docker to be installed. If
this exits with exit status 0, then everything is working!

```sh
$ make test
...
```

If you're developing a specific package, you can run tests for just that
package by specifying the `TEST` variable. For example below, only
`vault` package tests will be run.

```sh
$ make test TEST=./vault
...
```

### Importing OpenBao

This repository publishes two libraries that may be imported by other projects:
`github.com/openbao/openbao/api/v2` and `github.com/openbao/openbao/sdk/v2`.

Note that this repository also contains OpenBao (the product), and as with most Go
projects, OpenBao uses Go modules to manage its dependencies. The mechanism to do
that is the [go.mod](./go.mod) file. As it happens, the presence of that file
also makes it theoretically possible to import OpenBao as a dependency into other
projects. Some other projects have made a practice of doing so in order to take
advantage of testing tooling that was developed for testing OpenBao itself. This
is not, and has never been, a supported way to use the OpenBao project. We aren't
likely to fix bugs relating to failure to import `github.com/openbao/openbao`
into your project.

See also the section "Docker-based tests" below.

### Acceptance Tests

OpenBao has comprehensive [acceptance tests](https://en.wikipedia.org/wiki/Acceptance_testing)
covering most of the features of the secret and auth methods.

If you're working on a feature of a secret or auth method and want to
verify it is functioning (and also hasn't broken anything else), we recommend
running the acceptance tests.

**Warning:** The acceptance tests create/destroy/modify *real resources*, which
may incur real costs in some cases. In the presence of a bug, it is technically
possible that broken backends could leave dangling data behind. Therefore,
please run the acceptance tests at your own risk. At the very least,
we recommend running them in their own private account for whatever backend
you're testing.

To run the acceptance tests, invoke `make testacc`:

```sh
$ make testacc TEST=./builtin/logical/pki
...
```

The `TEST` variable is required, and you should specify the folder where the
backend is. The `TESTARGS` variable is recommended to filter down to a specific
resource to test, since testing all of them at once can sometimes take a very
long time.

Acceptance tests typically require other environment variables to be set for
things such as access keys. The test itself should error early and tell
you what to set, so it is not documented here.

### Docker-based Tests

We have created an experimental new testing mechanism inspired by NewTestCluster.
An example of how to use it:

```go
import (
  "testing"
  "github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
)

func Test_Something_With_Docker(t *testing.T) {
  opts := &docker.DockerClusterOptions{
    ImageRepo: "openbao/openbao",
    ImageTag:    "latest",
  }
  cluster := docker.NewTestDockerCluster(t, opts)
  defer cluster.Cleanup()

  client := cluster.Nodes()[0].APIClient()
  _, err := client.Logical().Read("sys/storage/raft/configuration")
  if err != nil {
    t.Fatal(err)
  }
}
```

Here is a more realistic example of how we use it in practice.  `DefaultOptions` uses
`hashicorp/vault:latest` as the repo and tag, but it also looks at the environment
variable `BAO_BINARY`. If populated, it will copy the local file referenced by
`BAO_BINARY` into the container. This is useful when testing local changes.

Optionally you can set `COMMIT_SHA`, which will be appended to the image name we
build as a debugging convenience.

```go
func Test_Custom_Build_With_Docker(t *testing.T) {
  opts := docker.DefaultOptions(t)
  cluster := docker.NewTestDockerCluster(t, opts)
  defer cluster.Cleanup()
}
```

Finally, here's an example of running an existing OSS docker test with a custom binary:

```bash
$ GOOS=linux make dev
$ VAULT_BINARY=$(pwd)/bin/bao go test -run 'TestRaft_Configuration_Docker' ./vault/external_tests/raft/raft_binary
ok      github.com/openbao/openbao/vault/external_tests/raft/raft_binary        20.960s
```
