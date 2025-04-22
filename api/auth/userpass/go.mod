module github.com/openbao/openbao/api/auth/userpass/v2

go 1.23.0

toolchain go1.23.7

replace github.com/openbao/openbao/api/v2 => ../../

require github.com/openbao/openbao/api/v2 v2.1.0

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/time v0.11.0 // indirect
)

retract v2.0.0
