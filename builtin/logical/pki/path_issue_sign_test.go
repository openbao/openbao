// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// Test issuing a certificate against a CEL role that specifies generate_lease and no_store
func TestCelRoleIssueWithGenerateLeaseAndNoStore(t *testing.T) {
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
					"name":       "small_ttl",
					"expression": `has(request.ttl) && duration(request.ttl) < duration("4h")`,
				},
				{
					"name":       "cn_value",
					"expression": "request.common_name",
				},
			},
			"expressions": map[string]interface{}{
				"requestId": "123",
				"success":   "validate_cn",
				"certificate": map[string]interface{}{
					"subject": map[string]interface{}{
						"common_name": "cn_value",
					},
				},
				"generateLease": "small_ttl",
				"noStore":       "!small_ttl",
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
		"format":              "pem",
		"common_name":         "example2.com",
		"ttl":                 "1h",
		"ip_sans":             "192.168.1.1,10.0.0.1",
		"key_usage":           "certsign",
		"ext_key_usage":       "ClientAuth",
		"policy_identifiers":  "1.3.6.1.4.1.1.1",
		"not_before_duration": 60,
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
	listResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs",
		Storage:   storage,
	})
	if err != nil || (listResp != nil && listResp.IsError()) {
		t.Fatalf("bad: err: %v listResp: %#v", err, listResp)
	}

	// check no_store works
	if len(listResp.Data["keys"].([]string)) != 2 {
		t.Fatalf("Both the CA and end certificate should be stored: %#v", listResp)
	}

	// Validate KeyUsage
	expectedKeyUsage := x509.KeyUsageCertSign
	if cert.KeyUsage&expectedKeyUsage == 0 {
		t.Fatalf("Certificate does not have expected KeyUsageCertSign: %v", cert.KeyUsage)
	}

	// Validate ExtKeyUsage
	if len(cert.ExtKeyUsage) != 1 {
		t.Fatalf("expected 1 ExtKeyUsage got %v: %v", len(cert.ExtKeyUsage), cert.ExtKeyUsage)
	}

	expectedExtKeyUsage := x509.ExtKeyUsageClientAuth
	if cert.ExtKeyUsage[0] != expectedExtKeyUsage {
		t.Fatalf("Certificate does not have expected ExtKeyUsageClientAuth: %v", cert.KeyUsage)
	}
}

// Test signing a certificate against a CEL role
func TestCelRoleSign(t *testing.T) {
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

	// Create a CEL role for signing
	roleData := map[string]interface{}{
		"validation_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "validate_cn",
					"expression": `has(request.common_name) && request.common_name == "example2.com"`,
				},
			},
			"expressions": map[string]interface{}{
				"success":       "validate_cn",
				"generateLease": "true",
				"noStore":       "false",
				"issuer":        "default",
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

	// Generate a CSR (Certificate Signing Request)
	identifiers := []string{"example.com"}
	goodCr := &x509.CertificateRequest{DNSNames: []string{identifiers[0]}}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, goodCr, csrKey)
	require.NoError(t, err, "failed generating csr")

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
	t.Logf("Generated CSR PEM:\n%s", csrPEM)

	// Issue a certificate using the CEL role and CSR
	signData := map[string]interface{}{
		"csr":         csrPEM,
		"common_name": "example2.com",
	}

	signReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/sign/testrole",
		Storage:   storage,
		Data:      signData,
	}

	resp, err = b.HandleRequest(context.Background(), signReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to sign certificate with CSR: err: %v, \nresp: %v", err, resp)
	}

	// // Validate the response
	// certPEM, ok := resp.Data["certificate"].(string)
	// if !ok || certPEM == "" {
	// 	t.Fatalf("Certificate not found in response: %v", resp.Data)
	// }

	// block, _ := pem.Decode([]byte(certPEM))
	// if block == nil || block.Type != "CERTIFICATE" {
	// 	t.Fatalf("Failed to decode certificate PEM: %v", certPEM)
	// }

	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	t.Fatalf("Failed to parse signed certificate: %v", err)
	// }

	// // Validate Key Usage
	// expectedKeyUsage := x509.KeyUsageCertSign
	// if cert.KeyUsage&expectedKeyUsage == 0 {
	// 	t.Fatalf("Certificate does not have expected KeyUsageCertSign: %v", cert.KeyUsage)
	// }

	// // Validate ExtKeyUsage
	// expectedExtKeyUsage := x509.ExtKeyUsageClientAuth
	// if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != expectedExtKeyUsage {
	// 	t.Fatalf("Certificate does not have expected ExtKeyUsageClientAuth: %v", cert.ExtKeyUsage)
	// }

	// // Validate Lease
	// if resp.Secret == nil {
	// 	t.Fatalf("Expected a lease-managed response, but none found")
	// }
}
