# OpenBao

----

**Please note**: We take OpenBao's security and our users' trust
very seriously. If you believe you have found a security issue
in OpenBao, _please responsibly disclose_ by contacting us at
[openbao-security@lists.openssf.org](mailto:openbao-security@lists.openssf.org).

----

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/openbao/openbao/badge)](https://scorecard.dev/viewer/?uri=github.com/openbao/openbao) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9126/badge)](https://www.bestpractices.dev/projects/9126)

- [Website](https://www.openbao.org)
- [Mailing List](https://lists.openssf.org/g/openbao)
- [GitHub Discussions](https://github.com/openbao/openbao/discussions)
- [Chat Server](https://linuxfoundation.zulipchat.com/)
  - [`#openssf-openbao-discussion`](https://linuxfoundation.zulipchat.com/#narrow/channel/529890-openssf-openbao-discussion)
  - [`#openssf-openbao-support`](https://linuxfoundation.zulipchat.com/#narrow/channel/530381-openssf-openbao-support)
  - [`#openssf-openbao-tsc`](https://linuxfoundation.zulipchat.com/#narrow/channel/530382-openssf-openbao-tsc)
  - Working Groups:
    - [`#openssf-openbao-wg`](https://linuxfoundation.zulipchat.com/#narrow/channel/574533-openssf-openbao-wg)
    - [`#openssf-openbao-wg-namespaces`](https://linuxfoundation.zulipchat.com/#narrow/channel/532995-openssf-openbao-wg-namespaces)
    - [`#openssf-openbao-wg-pkcs11`](https://linuxfoundation.zulipchat.com/#narrow/channel/532994-openssf-openbao-wg-pkcs11)
    - [`#openssf-openbao-wg-scalability`](https://linuxfoundation.zulipchat.com/#narrow/channel/532998-openssf-openbao-wg-scalability)
    - [`#openssf-openbao-wg-supply`](https://linuxfoundation.zulipchat.com/#narrow/channel/532999-openssf-openbao-wg-supply)
    - [`#openssf-openbao-wg-ui`](https://linuxfoundation.zulipchat.com/#narrow/channel/532997-openssf-openbao-wg-ui)

<p align="center">
  <img width="300" alt="OpenBao Mascot" src="https://raw.githubusercontent.com/openbao/artwork/main/color/openbao-color.svg">
</p>

**OpenBao is a software solution to manage, store, and distribute sensitive
data including secrets, certificates, and keys. The OpenBao community intends
to provide this software under an OSI-approved open-source license, led by a
community run under open-governance principles.**

A modern system requires access to a multitude of secrets: database credentials,
API keys for external services, credentials for service-oriented architecture
communication, etc. Understanding who is accessing what secrets is already very
difficult and platform-specific. Adding on key rolling, secure storage, and
detailed audit logs is almost impossible without a custom solution. This is
where OpenBao steps in.

The key features of OpenBao are:

* **Secure Secret Storage**: Arbitrary key/value secrets can be stored in
  OpenBao. OpenBao encrypts these secrets prior to writing them to persistent
  storage, so gaining access to the raw storage isn't enough to access your
  secrets. OpenBao can write to disk, [PostgreSQL](https://www.postgresql.org/),
  and more.

* **Dynamic Secrets**: OpenBao can generate secrets on-demand for some systems,
  such as AWS or SQL databases. For example, when an application needs to access
  an S3 bucket, it asks OpenBao for credentials, and OpenBao will generate an
  AWS keypair with valid permissions on demand. After creating these dynamic
  secrets, OpenBao will also automatically revoke them after the lease is up.

* **Data Encryption**: OpenBao can encrypt and decrypt data without storing it.
  This allows security teams to define encryption parameters and developers to
  store encrypted data in a location such as a SQL database without having to
  design their own encryption methods.

* **Leasing and Renewal**: All secrets in OpenBao have a _lease_ associated with
  them. At the end of the lease, OpenBao will automatically revoke that secret.
  Clients are able to renew leases via built-in renew APIs.

* **Revocation**: OpenBao has built-in support for secret revocation. OpenBao
  can revoke not only single secrets, but a tree of secrets, for example,
  all secrets read by a specific user, or all secrets of a particular type.
  Revocation assists in key rolling as well as locking down systems in the case
  of an intrusion.

## Documentation and Getting Started

Documentation is available on the [OpenBao website](https://openbao.org/docs/).

## Developing OpenBao

> [!WARNING]
> Before submitting pull requests to OpenBao, ensure that you have
> read and understood our contribution guidelines described in
> [`CONTRIBUTING.md`](./CONTRIBUTING.md). A failure to do so will likely result
> in your pull request being rejected.

If you wish to work on OpenBao itself or any of its built-in systems,
you'll first need [Go](https://www.golang.org) installed on your
machine. The Go toolchain version used in CI and releases is pinned at
[`.go-version`](./.go-version), but using the latest toolchain available for
local development is typically fine.

OpenBao uses [Go Modules](https://github.com/golang/go/wiki/Modules), so it is
recommended that you clone the repository ***outside*** of the GOPATH.

To build a `bao` binary:

```sh
$ mkdir -p bin
$ go build -o bin/bao .
```

To run the OpenBao server in development mode:

```sh
$ go run . server -dev # Or `./bin/bao server -dev` if you've built the binary already.
```

Since OpenBao is a large codebase that takes a short while to compile from a
cold cache, it is useful to attach the `-v` flag to build commands to get a
better sense of compilation progress.

To test a package:

```sh
$ go test ./some/package
```

Some additional notes on development:

- There is also a [`Makefile`](./Makefile) available for advanced build
  configurations and maintenance tasks. It is not required to build, run & debug
  OpenBao in most cases, but is worth a look.
- This repository also houses OpenBao's website and documentation page
  just as OpenBao's web UI application under the [`website`](./website)
  and [`ui`](./ui) subtrees respectively. Development instructions
  are available at [`website/README.md`](./website/README.md) and
  [`ui/README.md`](./ui/README.md).

### Importing OpenBao

This repository publishes two libraries that may be imported by other projects:
`github.com/openbao/openbao/api/v2` and `github.com/openbao/openbao/sdk/v2`.

Note that this repository also contains OpenBao (the application), and as
with most Go projects, OpenBao uses Go modules to manage its dependencies.
The mechanism to do that is the [`go.mod`](./go.mod) file. As it happens, the
presence of that file also makes it theoretically possible to import OpenBao
as a dependency into other projects. Some other projects have made a practice
of doing so in order to take advantage of testing tooling that was developed
for testing OpenBao itself. This is NOT, and has NEVER been, a supported way
to use the OpenBao project. We will not fix bugs relating to failure to import
`github.com/openbao/openbao` into your project or refactor internal code to make
this easier to do.
