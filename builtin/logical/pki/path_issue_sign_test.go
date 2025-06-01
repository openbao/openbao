// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// TestCelRoleIssueWithGenerateLeaseAndNoStore issuing a certificate against a CEL role that specifies generate_lease and no_store
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

	// Modify our issuer to set custom AIAs
	resp0, err := CBPatch(b, storage, "issuer/default", map[string]interface{}{
		"ocsp_servers": "http://localhost/c",
	})
	requireSuccessNonNilResponse(t, resp0, err, "failed setting up issuer")

	// Create a CEL role
	roleData := map[string]interface{}{
		"cel_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "validate_cn",
					"expression": `has(request.common_name) && request.common_name == "example.com"`,
				},
				{
					"name":       "small_ttl",
					"expression": `has(request.ttl) && duration(request.ttl) < duration("4h")`,
				},
				{
					"name":       "cn_value",
					"expression": "request.common_name",
				},
				{
					"name":       "not_after",
					"expression": "now + duration(request.ttl)",
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{                   
							CommonName: cn_value,
							Country:    ["ZW", "US"],     
						},
						NotBefore: now,
						NotAfter: not_after,
						IsCA: true,
						MaxPathLen: 10,	
						PolicyIdentifiers: [
							ObjectIdentifier{ arc: [1u, 2u, 3u] },
							ObjectIdentifier{ arc: [2u, 59u, 1u] },
						],
						IPAddresses: [
							net.IP{
								IP: b"\x0A\x00\x00\x00"
							}
						],
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,
						generate_lease:  small_ttl,
						no_store:        !small_ttl,
						issuer_ref:         "default",
						key_type: request.key_type,
						key_bits: uint(request.key_bits),
					  }`,
				},
				{
					"name":       "err",
					"expression": "'Request should have Common name: ' + cn_value",
				},
			},
			"expression": "validate_cn ? output : err",
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
		"common_name":         "example.com",
		"ttl":                 "1h",
		"ip_sans":             "192.168.1.1,10.0.0.1",
		"policy_identifiers":  "1.3.6.1.4.1.1.1",
		"not_before_duration": 60,
		"key_type":            "ec",
		"key_bits":            256,
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

	// Validate the OCSP Server
	expectedOCSPServer := "http://localhost/c"
	if len(cert.OCSPServer) != 1 && expectedOCSPServer != cert.OCSPServer[0] {
		t.Fatalf("Expected OCSPServer %v, but got: %v", expectedOCSPServer, cert.OCSPServer)
	}

	// Validate that only the IP Address specified in the template is in the final certificate      g
	expectedIP := net.ParseIP("10.0.0.0")
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(expectedIP) {
		t.Fatalf("Expected IP address %v, but got: %v", expectedIP, cert.IPAddresses)
	}

	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected an EC public key, got %T", cert.PublicKey)
	}
	if pk.Curve != elliptic.P256() || pk.Params().BitSize != 256 {
		t.Fatalf("expected P-256 (256-bit) key, got curve %s with %d bits",
			pk.Params().Name, pk.Params().BitSize)
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
}

// TestCelRoleSign signing a certificate against a CEL role
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
		"cel_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "validate_cn",
					"expression": `has(request.common_name) && request.common_name == "example2.com"`,
				},
				{
					"name":       "cn_value",
					"expression": "request.common_name",
				},
				{
					"name":       "not_after",
					"expression": "now + duration(request.ttl)",
				},
				{
					"name":       "emails",
					"expression": `parsed_csr.EmailAddresses`,
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{                   
							CommonName: cn_value,
							Country:    ["ZW", "US"],     
						},
						NotBefore: now,
						NotAfter: not_after,
						IsCA: true,
						MaxPathLen: 10,	
						PolicyIdentifiers: [
							ObjectIdentifier{ arc: [1u, 2u, 3u] },
							ObjectIdentifier{ arc: [2u, 59u, 1u] },
						],
						IPAddresses: [
							net.IP{
								IP: b"\x0A\x00\x00\x00"
							}
						],
						EmailAddresses: emails,		
						KeyUsage: 32,
						ExtKeyUsage: [2],
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,
						generate_lease: true,
						no_store:       false,
						issuer_ref:         "default",
						warnings: '',
					}`,
				},
				{
					"name":       "err",
					"expression": "'Request should have Common name: ' + request.common_name",
				},
			},
			"expression": "validate_cn ? output : err",
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
	goodCr := &x509.CertificateRequest{
		DNSNames:       []string{identifiers[0]},
		EmailAddresses: []string{"admin@example.com"},
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed generating ecdsa key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, goodCr, csrKey)
	require.NoError(t, err, "failed generating csr")

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	// Issue a certificate using the CEL role and CSR
	signData := map[string]interface{}{
		"csr":           csrPEM,
		"common_name":   "example2.com",
		"key_usage":     "certsign",
		"ext_key_usage": "ClientAuth",
		"ttl":           "1h",
	}

	signReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/sign/testrole",
		Storage:   storage,
		Data:      signData,
	}

	resp, err = b.HandleRequest(context.Background(), signReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to sign certificate with CSR: %v, \nresp: %v", err, resp)
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
		t.Fatalf("Failed to parse signed certificate: %v", err)
	}

	// Validate Key Usage
	expectedKeyUsage := x509.KeyUsageCertSign
	if cert.KeyUsage&expectedKeyUsage == 0 {
		t.Fatalf("Certificate does not have expected KeyUsageCertSign: %v", cert.KeyUsage)
	}

	// Validate ExtKeyUsage
	expectedExtKeyUsage := x509.ExtKeyUsageClientAuth
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != expectedExtKeyUsage {
		t.Fatalf("Certificate does not have expected ExtKeyUsageClientAuth: %v", cert.ExtKeyUsage)
	}

	// Validate Lease
	if resp.Secret == nil {
		t.Fatalf("Expected a lease-managed response, but none found")
	}
}

// TestCelRoleIssueWithMultipleRootsPresent issuing a certificate against a CEL role where multiple roots are present
func TestCelRoleIssueWithMultipleRootsPresent(t *testing.T) {
	t.Parallel()

	b, storage := CreateBackendWithStorage(t)

	// Create a root CA
	caData := map[string]interface{}{
		"common_name": "root.com",
		"ttl":         "30h",
		"locality":    "MiltonPark",
		"issuer_name": "first_root",
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

	// Create a second root CA
	caData2 := map[string]interface{}{
		"common_name": "root2.com",
		"ttl":         "30h",
		"locality":    "MiltonPark",
		"issuer_name": "second_root",
	}
	caReq2 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      caData2,
	}
	caResp2, err := b.HandleRequest(context.Background(), caReq2)
	if err != nil || (caResp2 != nil && caResp2.IsError()) {
		t.Fatalf("Failed to initialize CA: err: %v, resp: %#v", err, caResp2)
	}

	// Validate the response
	CAcertPEM2, ok := caResp2.Data["certificate"].(string)
	if !ok || CAcertPEM2 == "" {
		t.Fatalf("Certificate not found in response: %v", caResp2.Data)
	}

	CAblock2, _ := pem.Decode([]byte(CAcertPEM2))
	if CAblock2 == nil || CAblock2.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM2)
	}

	CAcert2, err := x509.ParseCertificate(CAblock2.Bytes)
	if err != nil && CAcert2 != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"cel_program": map[string]interface{}{
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
				{
					"name":       "not_after",
					"expression": "now + duration('3h')",
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{                   
							CommonName: cn_value,
							Country:    ["ZW", "US"],     
						},
						NotBefore: now,
						NotAfter: not_after,
						IsCA: false,						
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,
						generate_lease: small_ttl,
						no_store:       !small_ttl,
						issuer_ref:         "second_root",
						warnings: '',
					}`,
				},
				{
					"name":       "err",
					"expression": "'Request should have Common name: ' +  cn_value",
				},
			},
			"expression": "validate_cn ? output : err",
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
	expectedTTL := 3 * time.Hour
	actualTTL := cert.NotAfter.Sub(cert.NotBefore)
	if diff := actualTTL - expectedTTL; diff < -1*time.Minute || diff > 1*time.Minute {
		t.Fatalf("Expected TTL: %v ± 1m, but got: %v", expectedTTL, actualTTL)
	}

	// Validate the issuer (should be second_root)
	if cert.Issuer.CommonName != "root2.com" {
		t.Fatalf("Expected issuer to be root2.com, but got: %s", cert.Issuer.CommonName)
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

	// check 3 certs are stored (2 CA + 1 end cert)
	if len(listResp.Data["keys"].([]string)) != 3 {
		t.Fatalf("Two CA and one end certificate should be stored: %#v", listResp)
	}
}

// TestCelParsedCsr with CSR extensions being validated by CEL Role
func TestCelParsedCsr(t *testing.T) {
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
		"cel_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "validate_cn",
					"expression": `parsed_csr.Subject.CommonName == "example.com"`,
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{                   
							CommonName: parsed_csr.Subject.CommonName,
						},
						NotBefore: now,
						NotAfter: now + duration('3h'),						
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,
						generate_lease: true,
						no_store:       false,
						warnings: '',
					}`,
				},
				{
					"name":       "err",
					"expression": "'Request should have Common name: ' +  parsed_csr.Subject.CommonName",
				},
			},
			"expression": "validate_cn ? output : err",
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
	goodCr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: identifiers[0], // Correct placement of CN
		},
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed generating ecdsa key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, goodCr, csrKey)
	require.NoError(t, err, "failed generating csr")

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

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
		t.Fatalf("Failed to parse signed certificate: %v", err)
	}

	// Validate common_name is as in the CSR
	if cert.Subject.CommonName != "example.com" {
		t.Fatalf("Certificate should have common_name: 'example.com' instead has: '%v'", cert.Subject.CommonName)
	}
}

// TestCelCustomFunction custom CEL function
func TestCelCustomFunction(t *testing.T) {
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
		"cel_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "valid_emails",
					"expression": `check_valid_email(request.alt_names)`,
				},
				{
					"name":       "ttl",
					"expression": `duration(request.ttl) < duration('5h') ? duration('5h') : duration(request.ttl)`,
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{                   
							CommonName: request.common_name,
						},
						NotBefore: now,
						NotAfter: now + duration(ttl),
						EmailAddresses: [request.alt_names],		
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,						
						issuer_ref:         "default",
						warnings: duration(request.ttl) < duration('5h') ? 'ttl has been modified to 5h.' : '',
					  }`,
				},
				{
					"name":       "err",
					"expression": "'common_name should be a valid email.'",
				},
			},
			"expression": "valid_emails ? output : err",
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
		"common_name": "example.com",
		"alt_names":   "example@gmail.com",
		"ttl":         "4h",
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

	// Check warning is returned correctly
	const expectedWarn = "ttl has been modified to 5h."
	if resp == nil || len(resp.Warnings) == 0 || resp.Warnings[0] != expectedWarn {
		t.Fatalf("expected warning %q, got %v", expectedWarn, resp.Warnings)
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

	require.Equal(t, "example@gmail.com", cert.EmailAddresses[0], "Email Address should be example@gmail.com")
	require.Equal(t, "example.com", cert.Subject.CommonName, "Common Name should be example.com")
}

// TestNotAfter parameter that uses time duration
func TestNotAfter(t *testing.T) {
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

	// Modify our issuer to set custom AIAs
	resp0, err := CBPatch(b, storage, "issuer/default", map[string]interface{}{
		"ocsp_servers": "http://localhost/c",
	})
	requireSuccessNonNilResponse(t, resp0, err, "failed setting up issuer")

	// Create a CEL role
	roleData := map[string]interface{}{
		"cel_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "after",
					"expression": "timestamp(request.not_after)",
				},
				// Check notAfter is within the next 3 hours from now
				{
					"name":       "validate_after",
					"expression": "after < now + duration('3h')",
				},
				{
					"name":       "ttl",
					"expression": "(timestamp(request.not_after) - now)",
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						NotBefore: now,
						NotAfter: after,
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template:        cert,
					}`,
				},
				{
					"name":       "err",
					"expression": "'TTL should be > 3h, received ' + string(ttl)",
				},
			},
			"expression": "validate_after ? output : err",
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

	notAfter := time.Now().Add(time.Duration(time.Hour)).UTC().Format(time.RFC3339)

	// Issue a certificate using the CEL role
	issueData := map[string]interface{}{
		"common_name": "example.com",
		"not_after":   notAfter,
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
}
