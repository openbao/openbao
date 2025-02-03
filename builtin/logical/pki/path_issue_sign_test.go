// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Test issuing a certificate against a CEL role that specifies generate_lease
func TestCelRoleIssueWithGenerateLease(t *testing.T) {
	t.Parallel()

	b, storage := CreateBackendWithStorage(t)

	// Create a root CA
	caData := map[string]interface{}{
		"common_name": "root.com",
		"ttl":         "30h",
		"ip_sans":     "127.0.0.1",
		"locality":    "MiltonPark",
	}
	caReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      caData,
	}
	caResp, err := b.HandleRequest(context.Background(), caReq)
	if err != nil || (caResp != nil && caResp.IsError()) {
		t.Fatalf("Failed to initialize CA: err: %v, resp: %#v", err, caResp)
	}

	// Validate the response
	CAcertPEM, ok := caResp.Data["certificate"].(string)
	if !ok || CAcertPEM == "" {
		t.Fatalf("Certificate not found in response: %v", caResp.Data)
	}

	CAblock, _ := pem.Decode([]byte(CAcertPEM))
	if CAblock == nil || CAblock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM)
	}

	CAcert, err := x509.ParseCertificate(CAblock.Bytes)
	if err != nil && CAcert != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"validation_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "validate_cn",
					"expression": `has(request.common_name) && request.common_name == "example2.com"`,
				},
				{
					"name":       "cn_value",
					"expression": "request.common_name",
				},
				// {
				// 	"name":       "dns_san_value",
				// 	"expression": `has(request.dns_sans) && request.dns_sans == ["my.example.com"]`,
				// },
				// {
				// 	"name":       "dns_san_missing_value",
				// 	"expression": `request.dns_sans == ["my.example.com"] ? '' : 'adding my.example.com'`,
				// },
			},
			"expressions": map[string]interface{}{
				"requestId": "123",
				"success":   "validate_cn",
				"certificate": map[string]interface{}{
					"subject": map[string]interface{}{
						"common_name": "cn_value",
					},
				},
				"generateLease": "validate_cn",
				"noStore":       "validate_cn",
				"issuer":        "default",
				"warnings":      "warning",
				"error":         "error!",
			},
		},
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err := b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to create CEL role: err: %v, resp: %v", err, resp)
	}

	// Issue a certificate using the CEL role
	issueData := map[string]interface{}{
		"format":      "pem",
		"common_name": "example2.com",
		"ttl":         "1h",
		"ip_sans":     "192.168.1.1,10.0.0.1",
		// "dns_sans":    "my.example.com",
	}

	issueReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/issue/testrole",
		Storage:   storage,
		Data:      issueData,
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to issue certificate: err: %v, \nresp: %v", err, resp)
	}

	// Validate the response
	certPEM, ok := resp.Data["certificate"].(string)
	if !ok || certPEM == "" {
		t.Fatalf("Certificate not found in response: %v", resp.Data)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", certPEM)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Validate the TTL
	expectedTTL := 1 * time.Hour
	actualTTL := cert.NotAfter.Sub(cert.NotBefore)
	if diff := actualTTL - expectedTTL; diff < -1*time.Minute || diff > 1*time.Minute {
		t.Fatalf("Expected TTL: %v ± 1m, but got: %v", expectedTTL, actualTTL)
	}

	// check generate_lease works
	if resp.Secret == nil {
		t.Fatalf("expected a response that contains a secret")
	}

	// list certs
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// check no_store works
	if len(resp.Data["keys"].([]string)) != 1 {
		t.Fatalf("Only the CA certificate should be stored: %#v", resp)
	}
}
