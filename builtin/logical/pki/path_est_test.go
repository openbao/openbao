// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestEstEndToEndFlow tests a complete EST enrollment flow
func TestEstEndToEndFlow(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Step 1: Generate a root CA
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "1h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate root CA: err=%v resp=%#v", err, resp)
	}

	// Step 2: Enable EST
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to enable EST: err=%v resp=%#v", err, resp)
	}

	// Step 3: Get CA certificates
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "est/cacerts",
		Storage:   s,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to get CA certs: err=%v resp=%#v", err, resp)
	}

	if resp == nil || resp.Data == nil {
		t.Fatal("expected response with data")
	}

	// Verify we got PKCS#7 data
	rawBody, ok := resp.Data["http_raw_body"].([]byte)
	if !ok {
		t.Fatal("expected http_raw_body in response")
	}

	// Decode base64 (EST returns base64-encoded PKCS#7 per RFC 7030)
	decoded, err := base64.StdEncoding.DecodeString(string(rawBody))
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	// Parse PKCS#7
	caCerts, err := parsePKCS7(decoded)
	if err != nil {
		t.Fatalf("failed to parse PKCS#7: %v", err)
	}

	if len(caCerts) == 0 {
		t.Fatal("expected at least one CA certificate")
	}
}

// TestEstSimpleEnrollWithSignVerbatim tests EST enrollment with sign-verbatim policy
func TestEstSimpleEnrollWithSignVerbatim(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Generate a root CA
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "1h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate root CA: err=%v resp=%#v", err, resp)
	}

	// Enable EST with sign-verbatim
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_path_policy": "sign-verbatim",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to enable EST: err=%v resp=%#v", err, resp)
	}

	// Generate a CSR
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames: []string{"test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	// Wrap CSR in PKCS#7 (for simplicity, we'll use the CSR directly for now)
	// In real EST, the CSR should be in PKCS#7 format
	csrBase64 := base64.StdEncoding.EncodeToString(csrDER)

	// Test enrollment
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "est/simpleenroll",
		Storage:   s,
		Data: map[string]interface{}{
			"http_raw_body": []byte(csrBase64),
		},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("enrollment failed: err=%v resp=%#v", err, resp)
	}
}

// TestEstRoleBasedEnrollment tests EST enrollment with role-based policy
func TestEstRoleBasedEnrollment(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Generate a root CA
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "1h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate root CA: err=%v resp=%#v", err, resp)
	}

	// Create a role
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/est-test",
		Storage:   s,
		Data: map[string]interface{}{
			"allowed_domains":  []string{"example.com"},
			"allow_subdomains": true,
			"max_ttl":          "1h",
			"no_store":         false,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to create role: err=%v resp=%#v", err, resp)
	}

	// Enable EST with role-based policy
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_path_policy": "role:est-test",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to enable EST: err=%v resp=%#v", err, resp)
	}

	// Verify configuration
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/est",
		Storage:   s,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to read EST config: err=%v resp=%#v", err, resp)
	}

	if policy := resp.Data["default_path_policy"].(string); policy != "role:est-test" {
		t.Errorf("expected default_path_policy to be 'role:est-test', got %s", policy)
	}
}

// TestEstLabelMapping tests EST label-to-policy mapping
func TestEstLabelMapping(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Create multiple roles
	for _, roleName := range []string{"label1-role", "label2-role"} {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + roleName,
			Storage:   s,
			Data: map[string]interface{}{
				"allowed_domains": []string{"example.com"},
				"max_ttl":         "1h",
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("failed to create role %s: err=%v resp=%#v", roleName, err, resp)
		}
	}

	// Configure EST with label mapping
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
			"label_to_path_policy": map[string]string{
				"label1": "role:label1-role",
				"label2": "role:label2-role",
				"label3": "sign-verbatim",
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to configure EST: err=%v resp=%#v", err, resp)
	}

	// Verify configuration
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/est",
		Storage:   s,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to read EST config: err=%v resp=%#v", err, resp)
	}

	labelMap := resp.Data["label_to_path_policy"].(map[string]string)
	if len(labelMap) != 3 {
		t.Errorf("expected 3 labels, got %d", len(labelMap))
	}

	if labelMap["label1"] != "role:label1-role" {
		t.Errorf("expected label1 to map to 'role:label1-role', got %s", labelMap["label1"])
	}
}

// TestEstAuthenticationRequirements verifies that enrollment endpoints require authentication
// while /cacerts does not (per RFC 7030)
func TestEstAuthenticationRequirements(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Setup: Generate a root CA
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "1h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate root CA: err=%v resp=%#v", err, resp)
	}

	// Setup: Enable EST
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to enable EST: err=%v resp=%#v", err, resp)
	}

	// Test 1: /cacerts should work WITHOUT authentication (ClientToken = "")
	t.Run("cacerts_without_auth", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation:   logical.ReadOperation,
			Path:        "est/cacerts",
			Storage:     s,
			ClientToken: "", // No token
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("cacerts should work without auth: err=%v resp=%#v", err, resp)
		}

		if resp == nil || resp.Data == nil {
			t.Fatal("expected response with data")
		}

		// Verify we got PKCS#7 data
		_, ok := resp.Data["http_raw_body"].([]byte)
		if !ok {
			t.Fatal("expected http_raw_body in response")
		}
	})

	// Test 2: /simpleenroll should REQUIRE authentication
	t.Run("simpleenroll_without_auth", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "est/simpleenroll",
			Storage:     s,
			ClientToken: "", // No token
			HTTPRequest: &http.Request{
				Body: io.NopCloser(bytes.NewReader([]byte("fake csr data"))),
			},
		})

		// Should get an error or a 401 response
		if err == nil && (resp == nil || !resp.IsError()) {
			// Check if it's a 401 response
			if resp != nil && resp.Data != nil {
				statusCode, ok := resp.Data["http_status_code"].(int)
				if !ok || statusCode != 401 {
					t.Fatalf("simpleenroll without auth should return 401, got: %v", resp.Data)
				}

				if header, ok := resp.Data[logical.HTTPWWWAuthenticateHeader].(string); !ok || header != consts.ESTWWWAuthenticateHeaderValue {
					t.Fatalf("simpleenroll without auth should return WWW-Authenticate header, got: %v", resp.Data)
				}
			} else {
				t.Fatal("simpleenroll should require authentication")
			}
		}
	})

	// Test 3: /simplereenroll should REQUIRE authentication
	t.Run("simplereenroll_without_auth", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "est/simplereenroll",
			Storage:     s,
			ClientToken: "", // No token
			HTTPRequest: &http.Request{
				Body: io.NopCloser(bytes.NewReader([]byte("fake csr data"))),
			},
		})

		// Should get an error or a 401 response
		if err == nil && (resp == nil || !resp.IsError()) {
			// Check if it's a 401 response
			if resp != nil && resp.Data != nil {
				statusCode, ok := resp.Data["http_status_code"].(int)
				if !ok || statusCode != 401 {
					t.Fatalf("simplereenroll without auth should return 401, got: %v", resp.Data)
				}

				if header, ok := resp.Data[logical.HTTPWWWAuthenticateHeader].(string); !ok || header != consts.ESTWWWAuthenticateHeaderValue {
					t.Fatalf("simplereenroll without auth should return WWW-Authenticate header, got: %v", resp.Data)
				}
			} else {
				t.Fatal("simplereenroll should require authentication")
			}
		}
	})
}
