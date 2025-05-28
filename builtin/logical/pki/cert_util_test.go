// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestPki_FetchCertBySerial(t *testing.T) {
	t.Parallel()
	b, storage := CreateBackendWithStorage(t)
	sc := b.makeStorageContext(ctx, storage)

	cases := map[string]struct {
		Req    *logical.Request
		Prefix string
		Serial string
	}{
		"valid cert": {
			&logical.Request{
				Storage: storage,
			},
			"certs/",
			"00:00:00:00:00:00:00:00",
		},
		"revoked cert": {
			&logical.Request{
				Storage: storage,
			},
			"revoked/",
			"11:11:11:11:11:11:11:11",
		},
	}

	// Test for colon-based paths in storage
	for name, tc := range cases {
		storageKey := fmt.Sprintf("%s%s", tc.Prefix, tc.Serial)
		err := storage.Put(context.Background(), &logical.StorageEntry{
			Key:   storageKey,
			Value: []byte("some data"),
		})
		if err != nil {
			t.Fatalf("error writing to storage on %s colon-based storage path: %s", name, err)
		}

		certEntry, err := fetchCertBySerial(sc, tc.Prefix, tc.Serial)
		if err != nil {
			t.Fatalf("error on %s for colon-based storage path: %s", name, err)
		}

		// Check for non-nil on valid/revoked certs
		if certEntry == nil {
			t.Fatalf("nil on %s for colon-based storage path", name)
		}

		// Ensure that cert serials are converted/updated after fetch
		expectedKey := tc.Prefix + normalizeSerial(tc.Serial)
		se, err := storage.Get(context.Background(), expectedKey)
		if err != nil {
			t.Fatalf("error on %s for colon-based storage path:%s", name, err)
		}
		if strings.Compare(expectedKey, se.Key) != 0 {
			t.Fatalf("expected: %s, got: %s", expectedKey, certEntry.Key)
		}
	}

	// Reset storage
	storage = &logical.InmemStorage{}

	// Test for hyphen-base paths in storage
	for name, tc := range cases {
		storageKey := tc.Prefix + normalizeSerial(tc.Serial)
		err := storage.Put(context.Background(), &logical.StorageEntry{
			Key:   storageKey,
			Value: []byte("some data"),
		})
		if err != nil {
			t.Fatalf("error writing to storage on %s hyphen-based storage path: %s", name, err)
		}

		certEntry, err := fetchCertBySerial(sc, tc.Prefix, tc.Serial)
		if err != nil || certEntry == nil {
			t.Fatalf("error on %s for hyphen-based storage path: err: %v, entry: %v", name, err, certEntry)
		}
	}
}

// Demonstrate that multiple OUs in the name are handled in an
// order-preserving way.
func TestPki_MultipleOUs(t *testing.T) {
	t.Parallel()
	var b backend
	fields := addCACommonFields(map[string]*framework.FieldSchema{})

	apiData := &framework.FieldData{
		Schema: fields,
		Raw: map[string]interface{}{
			"cn":  "example.com",
			"ttl": 3600,
		},
	}
	input := &inputBundle{
		apiData: apiData,
		role: &roleEntry{
			MaxTTL: 3600,
			OU:     []string{"Z", "E", "V"},
		},
	}
	cb, _, err := generateCreationBundle(&b, input, nil, nil)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	expected := []string{"Z", "E", "V"}
	actual := cb.Params.Subject.OrganizationalUnit

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Expected %v, got %v", expected, actual)
	}
}

func TestPki_PermitFQDNs(t *testing.T) {
	t.Parallel()
	var b backend
	fields := addCACommonFields(map[string]*framework.FieldSchema{})

	cases := map[string]struct {
		input            *inputBundle
		expectedDnsNames []string
		expectedEmails   []string
	}{
		"base valid case": {
			input: &inputBundle{
				apiData: &framework.FieldData{
					Schema: fields,
					Raw: map[string]interface{}{
						"common_name": "example.com.",
						"ttl":         3600,
					},
				},
				role: &roleEntry{
					AllowAnyName:     true,
					MaxTTL:           3600,
					EnforceHostnames: true,
				},
			},
			expectedDnsNames: []string{"example.com."},
			expectedEmails:   []string{},
		},
		"case insensitivity validation": {
			input: &inputBundle{
				apiData: &framework.FieldData{
					Schema: fields,
					Raw: map[string]interface{}{
						"common_name": "Example.Net",
						"alt_names":   "eXaMPLe.COM",
						"ttl":         3600,
					},
				},
				role: &roleEntry{
					AllowedDomains:   []string{"example.net", "EXAMPLE.COM"},
					AllowBareDomains: true,
					MaxTTL:           3600,
				},
			},
			expectedDnsNames: []string{"Example.Net", "eXaMPLe.COM"},
			expectedEmails:   []string{},
		},
		"case email as AllowedDomain with bare domains": {
			input: &inputBundle{
				apiData: &framework.FieldData{
					Schema: fields,
					Raw: map[string]interface{}{
						"common_name": "test@testemail.com",
						"ttl":         3600,
					},
				},
				role: &roleEntry{
					AllowedDomains:   []string{"test@testemail.com"},
					AllowBareDomains: true,
					MaxTTL:           3600,
				},
			},
			expectedDnsNames: []string{},
			expectedEmails:   []string{"test@testemail.com"},
		},
		"case email common name with bare domains": {
			input: &inputBundle{
				apiData: &framework.FieldData{
					Schema: fields,
					Raw: map[string]interface{}{
						"common_name": "test@testemail.com",
						"ttl":         3600,
					},
				},
				role: &roleEntry{
					AllowedDomains:   []string{"testemail.com"},
					AllowBareDomains: true,
					MaxTTL:           3600,
				},
			},
			expectedDnsNames: []string{},
			expectedEmails:   []string{"test@testemail.com"},
		},
	}

	for name, testCase := range cases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			cb, _, err := generateCreationBundle(&b, testCase.input, nil, nil)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			actualDnsNames := cb.Params.DNSNames

			if !reflect.DeepEqual(testCase.expectedDnsNames, actualDnsNames) {
				t.Fatalf("Expected dns names %v, got %v", testCase.expectedDnsNames, actualDnsNames)
			}

			actualEmails := cb.Params.EmailAddresses

			if !reflect.DeepEqual(testCase.expectedEmails, actualEmails) {
				t.Fatalf("Expected email addresses %v, got %v", testCase.expectedEmails, actualEmails)
			}
		})
	}
}

func TestPki_getCertificateNotBefore(t *testing.T) {
	data := inputBundle{
		role: &roleEntry{
			NotBefore: "2024-12-31T23:59:59Z",
		},
		apiData: &framework.FieldData{},
	}

	expectedNotBefore := "2024-12-31 23:59:59 +0000 UTC"

	notBefore, err := getCertificateNotBefore(&data)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if expectedNotBefore != notBefore.String() {
		t.Fatalf("Expected Not Before %v, got %v", expectedNotBefore, notBefore)
	}
}

func TestPki_getCertificateNotAfter_PastDate(t *testing.T) {
	t.Parallel()

	// Create a system view with default TTLs
	sysView := logical.TestSystemView()
	sysView.DefaultLeaseTTLVal = 24 * time.Hour
	sysView.MaxLeaseTTLVal = 24 * time.Hour

	// Create backend with the system view
	config := &logical.BackendConfig{
		StorageView: &logical.InmemStorage{},
		System:      sysView,
	}

	b := Backend(config)
	require.NotNil(t, b, "failed to create backend")

	err := b.Setup(context.Background(), config)
	require.NoError(t, err, "failed to setup backend")

	// Create a CA certificate with NotAfter in the future
	now := time.Now()
	caCert := &x509.Certificate{
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	}

	// Test case for past NotAfter date
	data := &inputBundle{
		role: &roleEntry{
			MaxTTL:        24 * time.Hour,
			TTL:           0,
			NotAfterBound: "permit",
		},
		apiData: &framework.FieldData{
			Raw: map[string]any{
				"not_after": now.Add(-1 * time.Hour).Format(time.RFC3339),
				"ttl":       0,
			},
			Schema: map[string]*framework.FieldSchema{
				"not_after": {Type: framework.TypeString},
				"ttl":       {Type: framework.TypeDurationSecond},
				"format":    {Type: framework.TypeString},
			},
		},
	}

	caBundle := &certutil.CAInfoBundle{
		ParsedCertBundle: certutil.ParsedCertBundle{
			Certificate: caCert,
		},
		LeafNotAfterBehavior: certutil.TruncateNotAfterBehavior,
	}

	// Test that we get an error when NotAfter is in the past
	result, warnings, err := getCertificateNotAfter(b, data, caBundle)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot satisfy request, as NotAfter date")
	require.True(t, time.Time{}.Equal(result))
	require.Empty(t, warnings)
}
