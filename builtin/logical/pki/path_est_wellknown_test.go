// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestEstWellKnownPaths tests EST well-known path functionality
func TestEstWellKnownPaths(t *testing.T) {
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

	// Enable EST with a label mapping
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_path_policy": "sign-verbatim",
			"label_to_path_policy": map[string]interface{}{
				"test-label": "sign-verbatim",
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to enable EST: err=%v resp=%#v", err, resp)
	}

	// Test 1: Access cacerts via standard .well-known/est/cacerts path
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/est/cacerts",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("failed to retrieve CA certs via well-known path: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected successful response, got: %#v", resp)
	}
	if resp.Data["http_content_type"] != estPKCS7ContentType {
		t.Fatalf("expected pkcs7-mime content type, got: %v", resp.Data["http_content_type"])
	}

	// Test 2: Access cacerts via labeled well-known path
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/est/test-label/cacerts",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("failed to retrieve CA certs via labeled well-known path: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected successful response, got: %#v", resp)
	}

	// Test 3: Verify invalid label returns error
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/est/invalid-label/cacerts",
		Storage:   s,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected error for invalid label, got successful response")
	}
}

func TestEstCacertsLabelUsesPathPolicy(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)
	ctx := context.Background()

	// Create the default root issuer
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Default EST Root",
			"ttl":         "720h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate default root: err=%v resp=%#v", err, resp)
	}
	defaultIssuerID := string(resp.Data["issuer_id"].(issuerID))

	// Create a second root issuer that will back the labeled path
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuers/generate/root/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "Label EST Root",
			"ttl":         "720h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to generate label root: err=%v resp=%#v", err, resp)
	}
	labelIssuerID := string(resp.Data["issuer_id"].(issuerID))

	createRole := func(name, issuerRef string) {
		roleData := map[string]interface{}{
			"allow_any_name": true,
			"max_ttl":        "1h",
		}
		if issuerRef != "" {
			roleData["issuer_ref"] = issuerRef
		}
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + name,
			Storage:   s,
			Data:      roleData,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("failed to create role %s: err=%v resp=%#v", name, err, resp)
		}
	}

	createRole("default-role", defaultIssuerID)
	createRole("label-role", labelIssuerID)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "role:default-role",
			"label_to_path_policy": map[string]interface{}{
				"label-ca": "role:label-role",
			},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to configure EST: err=%v resp=%#v", err, resp)
	}

	getRootCN := func(path string) string {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   s,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("failed to read %s: err=%v resp=%#v", path, err, resp)
		}
		rawBody, ok := resp.Data["http_raw_body"].([]byte)
		if !ok {
			t.Fatalf("expected http_raw_body in response for %s", path)
		}
		der, err := base64.StdEncoding.DecodeString(string(rawBody))
		if err != nil {
			t.Fatalf("failed to decode base64 body for %s: %v", path, err)
		}
		certs, err := parsePKCS7(der)
		if err != nil {
			t.Fatalf("failed to parse PKCS#7 for %s: %v", path, err)
		}
		if len(certs) == 0 {
			t.Fatalf("no certificates returned for %s", path)
		}
		return certs[0].Subject.CommonName
	}

	defaultCN := getRootCN(".well-known/est/cacerts")
	labelCN := getRootCN(".well-known/est/label-ca/cacerts")

	if defaultCN != "Default EST Root" {
		t.Fatalf("expected default path to return Default EST Root, got %s", defaultCN)
	}
	if labelCN != "Label EST Root" {
		t.Fatalf("expected labeled path to return Label EST Root, got %s", labelCN)
	}
	if defaultCN == labelCN {
		t.Fatalf("expected different CA chains for default and labeled paths")
	}
}

// TestEstWellKnownEnrollment tests EST enrollment via well-known paths
func TestEstWellKnownEnrollment(t *testing.T) {
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

	// Enable EST with label mappings
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_path_policy": "sign-verbatim",
			"label_to_path_policy": map[string]interface{}{
				"enroll": "sign-verbatim",
			},
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

	csrBase64 := base64.StdEncoding.EncodeToString(csrDER)

	// Test enrollment via well-known path with default label
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ".well-known/est/simpleenroll",
		Storage:   s,
		Data: map[string]interface{}{
			"http_raw_body": []byte(csrBase64),
		},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("enrollment via .well-known/est/simpleenroll failed: err=%v resp=%#v", err, resp)
	}

	// Test enrollment via well-known path with label
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ".well-known/est/enroll/simpleenroll",
		Storage:   s,
		Data: map[string]interface{}{
			"http_raw_body": []byte(csrBase64),
		},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("enrollment via .well-known/est/enroll/simpleenroll failed: err=%v resp=%#v", err, resp)
	}
}
