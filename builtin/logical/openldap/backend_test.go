// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"errors"
	"time"

	"github.com/go-ldap/ldif"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/builtin/logical/openldap/client"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/queue"
)

var (
	defaultLeaseTTLVal      = time.Hour * 12
	maxLeaseTTLVal          = time.Hour * 24
	testPasswordPolicy1     = "test_policy_1"
	testPasswordPolicy2     = "test_policy_2"
	testPasswordFromPolicy1 = "TestPolicy1Password"
	testPasswordFromPolicy2 = "TestPolicy2Password"
)

func getBackend(throwsErr bool) (*backend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Debug),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
			PasswordPolicies: map[string]logical.PasswordGenerator{
				testPasswordPolicy1: func() (string, error) {
					return testPasswordFromPolicy1, nil
				},
				testPasswordPolicy2: func() (string, error) {
					return testPasswordFromPolicy2, nil
				},
			},
		},
		StorageView: &logical.InmemStorage{},
	}

	b := Backend(&fakeLdapClient{throwErrs: throwsErr})
	b.Setup(context.Background(), config)

	b.credRotationQueue = queue.New()
	// Create a context with a cancel method for processing any WAL entries and
	// populating the queue
	initCtx := context.Background()
	ictx, cancel := context.WithCancel(initCtx)
	b.cancelQueue = cancel

	// Load queue and kickoff new periodic ticker
	b.initQueue(ictx, &logical.InitializationRequest{
		Storage: config.StorageView,
	})

	return b, config.StorageView
}

var _ ldapClient = (*fakeLdapClient)(nil)

type fakeLdapClient struct {
	throwErrs bool
}

func (f *fakeLdapClient) UpdateUserPassword(_ *client.Config, _ string, _ string) error {
	var err error
	if f.throwErrs {
		err = errors.New("forced error")
	}
	return err
}

func (f *fakeLdapClient) UpdateDNPassword(_ *client.Config, _ string, _ string) error {
	var err error
	if f.throwErrs {
		err = errors.New("forced error")
	}
	return err
}

func (f *fakeLdapClient) Execute(_ *client.Config, _ []*ldif.Entry, _ bool) (err error) {
	return errors.New("not implemented")
}

const validCertificate = `
-----BEGIN CERTIFICATE-----
MIIF7zCCA9egAwIBAgIJAOY2qjn64Qq5MA0GCSqGSIb3DQEBCwUAMIGNMQswCQYD
VQQGEwJVUzEQMA4GA1UECAwHTm93aGVyZTERMA8GA1UEBwwIVGltYnVrdHUxEjAQ
BgNVBAoMCVRlc3QgRmFrZTENMAsGA1UECwwETm9uZTEPMA0GA1UEAwwGTm9ib2R5
MSUwIwYJKoZIhvcNAQkBFhZkb25vdHRydXN0QG5vd2hlcmUuY29tMB4XDTE4MDQw
MzIwNDQwOFoXDTE5MDQwMzIwNDQwOFowgY0xCzAJBgNVBAYTAlVTMRAwDgYDVQQI
DAdOb3doZXJlMREwDwYDVQQHDAhUaW1idWt0dTESMBAGA1UECgwJVGVzdCBGYWtl
MQ0wCwYDVQQLDAROb25lMQ8wDQYDVQQDDAZOb2JvZHkxJTAjBgkqhkiG9w0BCQEW
FmRvbm90dHJ1c3RAbm93aGVyZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDzQPGErqjaoFcuUV6QFpSMU6w8wO8F0othik+rrlKERmrGonUGsoum
WqRe6L4ZnxBvCKB6EWjvf894TXOF2cpUnjDAyBePISyPkRBEJS6VS2SEC4AJzmVu
a+P+fZr4Hf7/bEcUr7Ax37yGVZ5i5ByNHgZkBlPxKiGWSmAqIDRZLp9gbu2EkG9q
NOjNLPU+QI2ov6U/laGS1vbE2LahTYeT5yscu9LpllxzFv4lM1f4wYEaM3HuOxzT
l86cGmEr9Q2N4PZ2T0O/s6D4but7c6Bz2XPXy9nWb5bqu0n5bJEpbRFrkryW1ozh
L9uVVz4dyW10pFBJtE42bqA4PRCDQsUof7UfsQF11D1ThrDfKsQa8PxrYdGUHUG9
GFF1MdTTwaoT90RI582p+6XYV+LNlXcdfyNZO9bMThu9fnCvT7Ey0TKU4MfPrlfT
aIhZmyaHt6mL5p881UPDIvy7paTLgL+C1orLjZAiT//c4Zn+0qG0//Cirxr020UF
3YiEFk2H0bBVwOHoOGw4w5HrvLdyy0ZLDSPQbzkSZ0RusHb5TjiyhtTk/h9vvJv7
u1fKJub4MzgrBRi16ejFdiWoVuMXRC6fu/ERy3+9DH6LURerbPrdroYypUmTe9N6
XPeaF1Tc+WO7O/yW96mV7X/D211qjkOtwboZC5kjogVbaZgGzjHCVwIDAQABo1Aw
TjAdBgNVHQ4EFgQU2zWT3HeiMBzusz7AggVqVEL5g0UwHwYDVR0jBBgwFoAU2zWT
3HeiMBzusz7AggVqVEL5g0UwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AgEAwTGcppY86mNRE43uOimeApTfqHJv+lGDTjEoJCZZmzmtxFe6O9+Vk4bH/8/i
gVQvqzBpaWXRt9OhqlFMK7OkX4ZvqXmnShmxib1dz1XxGhbwSec9ca8bill59Jqa
bIOq2SXVMcFD0GwFxfJRBVzHHuB6AwV9B2QN61zeB1oxNGJrUOo80jVkB7+MWMyD
bQqiFCHWGMa6BG4N91KGOTveZCGdBvvVw5j6lt731KjbvL2hB1UHioucOweKLfa4
QWDImTEjgV68699wKERNL0DCpeD7PcP/L3SY2RJzdyC1CSR7O8yU4lQK7uZGusgB
Mgup+yUaSjxasIqYMebNDDocr5kdwG0+2r2gQdRwc5zLX6YDBn6NLSWjRnY04ZuK
P1cF68rWteWpzJu8bmkJ5r2cqskqrnVK+zz8xMQyEaj548Bnt51ARLHOftR9jkSU
NJWh7zOLZ1r2UUKdDlrMoh3GQO3rvnCJJ16NBM1dB7TUyhMhtF6UOE62BSKdHtQn
d6TqelcRw9WnDsb9IPxRwaXhvGljnYVAgXXlJEI/6nxj2T4wdmL1LWAr6C7DuWGz
8qIvxc4oAau4DsZs2+BwolCFtYc98OjWGcBStBfZz/YYXM+2hKjbONKFxWdEPxGR
Beq3QOqp2+dga36IzQybzPQ8QtotrpSJ3q82zztEvyWiJ7E=
-----END CERTIFICATE-----
`
