// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// TestACME_ValidateIdentifiersAgainstRole Verify the ACME order creation
// function verifies somewhat the identifiers that were provided have a
// decent chance of being allowed by the selected role.
func TestACME_ValidateIdentifiersAgainstRole(t *testing.T) {
	b, _ := CreateBackendWithStorage(t)

	tests := []struct {
		name        string
		role        *roleEntry
		identifiers []*ACMEIdentifier
		expectErr   bool
	}{
		{
			name:        "verbatim-role-allows-dns-ip",
			role:        buildSignVerbatimRoleWithNoData(nil),
			identifiers: _buildACMEIdentifiers("test.com", "127.0.0.1"),
			expectErr:   false,
		},
		{
			name:        "default-role-does-not-allow-dns",
			role:        buildTestRole(t, nil),
			identifiers: _buildACMEIdentifiers("www.test.com"),
			expectErr:   true,
		},
		{
			name:        "default-role-allows-ip",
			role:        buildTestRole(t, nil),
			identifiers: _buildACMEIdentifiers("192.168.0.1"),
			expectErr:   false,
		},
		{
			name:        "disable-ip-sans-forbids-ip",
			role:        buildTestRole(t, map[string]any{"allow_ip_sans": false}),
			identifiers: _buildACMEIdentifiers("192.168.0.1"),
			expectErr:   true,
		},
		{
			name: "role-no-wildcards-allowed-without",
			role: buildTestRole(t, map[string]any{
				"allow_subdomains":            true,
				"allow_bare_domains":          true,
				"allowed_domains":             []string{"test.com"},
				"allow_wildcard_certificates": false,
			}),
			identifiers: _buildACMEIdentifiers("www.test.com", "test.com"),
			expectErr:   false,
		},
		{
			name: "role-no-wildcards-allowed-with-wildcard",
			role: buildTestRole(t, map[string]any{
				"allow_subdomains":            true,
				"allowed_domains":             []string{"test.com"},
				"allow_wildcard_certificates": false,
			}),
			identifiers: _buildACMEIdentifiers("*.test.com"),
			expectErr:   true,
		},
		{
			name: "role-wildcards-allowed-with-wildcard",
			role: buildTestRole(t, map[string]any{
				"allow_subdomains":            true,
				"allowed_domains":             []string{"test.com"},
				"allow_wildcard_certificates": true,
			}),
			identifiers: _buildACMEIdentifiers("*.test.com"),
			expectErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.validateIdentifiersAgainstRole(tt.role, tt.identifiers)

			if tt.expectErr {
				require.Error(t, err, "validateIdentifiersAgainstRole(%v, %v)", tt.role.ToResponseData(), tt.identifiers)
				// If we did return an error if should be classified as a ErrRejectedIdentifier
				require.ErrorIs(t, err, ErrRejectedIdentifier)
			} else {
				require.NoError(t, err, "validateIdentifiersAgainstRole(%v, %v)", tt.role.ToResponseData(), tt.identifiers)
			}
		})
	}
}

func _buildACMEIdentifiers(values ...string) []*ACMEIdentifier {
	var identifiers []*ACMEIdentifier

	for _, value := range values {
		identifiers = append(identifiers, _buildACMEIdentifier(value))
	}

	return identifiers
}

func _buildACMEIdentifier(val string) *ACMEIdentifier {
	ip := net.ParseIP(val)
	if ip == nil {
		identifier := &ACMEIdentifier{Type: "dns", Value: val, OriginalValue: val, IsWildcard: false}
		_, _, _ = identifier.MaybeParseWildcard()
		return identifier
	}

	return &ACMEIdentifier{Type: "ip", Value: val, OriginalValue: val, IsWildcard: false}
}

// Easily allow tests to create valid roles with proper defaults, since we don't have an easy
// way to generate roles with proper defaults, go through the createRole handler with the handlers
// field data so we pickup all the defaults specified there.
func buildTestRole(t *testing.T, config map[string]any) *roleEntry {
	b, s := CreateBackendWithStorage(t)

	path := pathRoles(b)
	fields := path.Fields
	if config == nil {
		config = map[string]any{}
	}

	if _, exists := config["name"]; !exists {
		config["name"] = genUuid()
	}

	_, err := b.pathRoleCreate(t.Context(), &logical.Request{Storage: s}, &framework.FieldData{Raw: config, Schema: fields})
	require.NoError(t, err, "failed generating role with config %v", config)

	role, err := b.getRole(t.Context(), s, config["name"].(string))
	require.NoError(t, err, "failed loading stored role")

	return role
}

func TestACME_ValidateCsrMatchesOrder(t *testing.T) {
	// A regular CSR with contents who
	type testCase struct {
		Csr     *x509.CertificateRequest
		Order   *acmeOrder
		Failure string
	}

	tests := []*testCase{
		{
			Csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.bar.com",
				},
				// This SAN comes from runTestSignVerbatim and is of type otherName.
				Extensions: []pkix.Extension{
					{
						Id:       oidExtensionSubjectAltName,
						Critical: false,
						Value:    []byte{0x30, 0x26, 0xA0, 0x24, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03, 0xA0, 0x16, 0x0C, 0x14, 0x75, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65, 0x40, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D},
					},
				},
			},
			Order: &acmeOrder{
				Identifiers: []*ACMEIdentifier{
					{
						Type:          ACMEDNSIdentifier,
						OriginalValue: "foo.bar.com",
					},
				},
			},
			Failure: "CSR included unsupported SAN types",
		},
		{
			Csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.bar.com",
				},
				// This SAN is of type DNS name.
				DNSNames: []string{"foo.bar.com"},
			},
			Order: &acmeOrder{
				Identifiers: []*ACMEIdentifier{
					{
						Type:          ACMEDNSIdentifier,
						OriginalValue: "foo.bar.com",
					},
				},
			},
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for index, test := range tests {
		err := validateCsrMatchesOrder(test.Csr, test.Order)
		if len(test.Failure) > 0 {
			require.ErrorContains(t, err, test.Failure, "test case: %v", index)
		} else {
			require.NoError(t, err, "test case: %v", index)
		}

		// Marshal and unmarshal CSR to ensure nothing changes.
		csrReq := *test.Csr
		csrReq.ExtraExtensions = csrReq.Extensions
		csrReq.Extensions = nil

		encoded, err := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
		require.NoError(t, err, "failed to marshal CSR: %v", index)

		csr, err := x509.ParseCertificateRequest(encoded)
		require.NoError(t, err, "failed to parse encoded CSR: %v", index)

		err = validateCsrMatchesOrder(csr, test.Order)
		if len(test.Failure) > 0 {
			require.ErrorContains(t, err, test.Failure, "test case: %v", index)
		} else {
			require.NoError(t, err, "test case: %v", index)
		}
	}
}
