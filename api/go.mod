module github.com/openbao/openbao/api/v2

// The Go version directive for the api package should normally only be updated when
// code in the api package requires a newer Go version to build.  It should not
// automatically track the Go version used to build Vault itself.  Many projects import
// the api module and we don't want to impose a newer version on them any more than we
// have to.
go 1.23.0

toolchain go1.23.8

require (
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/go-test/deep v1.1.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/hcl v1.0.1-vault-5
	github.com/mitchellh/mapstructure v1.5.0
	golang.org/x/net v0.36.0
	golang.org/x/time v0.9.0
)

require (
	github.com/fatih/color v1.18.0 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)

retract v2.0.0
