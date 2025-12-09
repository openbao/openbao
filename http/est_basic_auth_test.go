// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

// TestEstHttpBasicAuthSimpleEnroll tests EST simpleenroll with HTTP Basic Auth
func TestEstHttpBasicAuthSimpleEnroll(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	// Setup PKI
	setupPKIForEstTesting(t, client)

	// Setup userpass auth
	estUsername := "est-device"
	estPassword := "device-secret-123"
	setupUserpassForEst(t, client, estUsername, estPassword)

	// Configure EST with HTTP Basic Auth
	_, err := client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "role:est-devices",
		"authenticators": map[string]interface{}{
			"userpass": map[string]interface{}{
				"accessor": getUserpassAccessor(t, client),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	// Generate CSR
	csrDER := generateTestCSR(t, "test-device.example.com")

	// Test 1: simpleenroll with HTTP Basic Auth via root path
	t.Run("SimpleEnrollWithBasicAuthRootPath", func(t *testing.T) {
		cert := estSimpleEnrollWithBasicAuth(t, cluster, "/.well-known/est/simpleenroll",
			estUsername, estPassword, csrDER)
		if cert == nil {
			t.Fatal("expected certificate, got nil")
		}
		verifyCertificate(t, cert, "test-device.example.com")
	})

	// Test 2: simpleenroll with HTTP Basic Auth via mount path
	t.Run("SimpleEnrollWithBasicAuthMountPath", func(t *testing.T) {
		cert := estSimpleEnrollWithBasicAuth(t, cluster, "/v1/pki/.well-known/est/simpleenroll",
			estUsername, estPassword, csrDER)
		if cert == nil {
			t.Fatal("expected certificate, got nil")
		}
		verifyCertificate(t, cert, "test-device.example.com")
	})

	// Test 3: simpleenroll with wrong credentials should fail
	t.Run("SimpleEnrollWithWrongCredentials", func(t *testing.T) {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		httpClient := &http.Client{Transport: transport}

		req, err := http.NewRequest("POST", cluster.Cores[0].Client.Address()+"/.well-known/est/simpleenroll",
			bytes.NewReader(csrDER))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(estUsername, "wrong-password")
		req.Header.Set("Content-Type", "application/pkcs10")

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}

		header := resp.Header.Get("WWW-Authenticate")
		if header != consts.ESTWWWAuthenticateHeaderValue {
			t.Fatalf("expected WWW-Authenticate header %q, got %q", consts.ESTWWWAuthenticateHeaderValue, header)
		}
	})

	// Test 4: simpleenroll without credentials should fail
	t.Run("SimpleEnrollWithoutCredentials", func(t *testing.T) {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		httpClient := &http.Client{Transport: transport}

		req, err := http.NewRequest("POST", cluster.Cores[0].Client.Address()+"/.well-known/est/simpleenroll",
			bytes.NewReader(csrDER))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/pkcs10")

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		// Should get 401 Unauthorized or 403 Forbidden when no credentials provided
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 401 or 403, got %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusUnauthorized {
			header := resp.Header.Get("WWW-Authenticate")
			if header != consts.ESTWWWAuthenticateHeaderValue {
				t.Fatalf("expected WWW-Authenticate header %q, got %q", consts.ESTWWWAuthenticateHeaderValue, header)
			}
		}
	})
}

// Test re-enrollment with HTTP Basic Auth
func TestEstBasicAuthSimpleReenroll(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	// Setup
	setupPKIForEstTesting(t, client)
	estUsername := "est-device"
	estPassword := "device-secret-123"
	setupUserpassForEst(t, client, estUsername, estPassword)

	_, err := client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
		"authenticators": map[string]interface{}{
			"userpass": map[string]interface{}{
				"accessor": getUserpassAccessor(t, client),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	// First enroll a certificate
	csrDER1 := generateTestCSR(t, "test-device.example.com")
	cert1 := estSimpleEnrollWithBasicAuth(t, cluster, "/.well-known/est/simpleenroll",
		estUsername, estPassword, csrDER1)
	if cert1 == nil {
		t.Fatal("initial enrollment failed")
	}

	// Test reenroll with different CSR
	t.Run("SimpleReenrollWithBasicAuth", func(t *testing.T) {
		csrDER2 := generateTestCSR(t, "test-device-renewed.example.com")
		resp := estSimpleEnrollRequest(t, cluster, "/.well-known/est/simplereenroll", estUsername, estPassword, csrDER2)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 401 Unauthorized when TLS client cert missing, got %d: %s", resp.StatusCode, string(body))
		}

		header := resp.Header.Get("WWW-Authenticate")
		if header != consts.ESTWWWAuthenticateHeaderValue {
			t.Fatalf("expected WWW-Authenticate header %q, got %q", consts.ESTWWWAuthenticateHeaderValue, header)
		}
	})
}

// TestEstBasicAuthCacerts tests EST cacerts endpoint
func TestEstBasicAuthCacerts(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	setupPKIForEstTesting(t, client)

	_, err := client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	testCases := []struct {
		name string
		path string
	}{
		{"RootPath", "/.well-known/est/cacerts"},
		{"MountPath", "/v1/pki/.well-known/est/cacerts"},
		{"DirectEstPath", "/v1/pki/est/cacerts"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
			httpClient := &http.Client{Transport: transport}

			req, err := http.NewRequest("GET", cluster.Cores[0].Client.Address()+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
			}

			// Read and decode the response
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			// Response should be base64-encoded PKCS#7
			decoded, err := base64.StdEncoding.DecodeString(string(body))
			if err != nil {
				t.Fatalf("failed to decode base64 response: %v", err)
			}

			if len(decoded) == 0 {
				t.Fatal("empty decoded response")
			}

			// Should be valid DER-encoded data
			if decoded[0] != 0x30 {
				t.Fatal("response does not appear to be DER-encoded")
			}
		})
	}
}

// TestEstMountPathExtraction tests mount path extraction logic
func TestEstMountPathExtraction(t *testing.T) {
	testCases := []struct {
		name          string
		inputPath     string
		expectedMount string
	}{
		{
			name:          "WellKnownEstPath",
			inputPath:     "/v1/pki/.well-known/est/simpleenroll",
			expectedMount: "pki",
		},
		{
			name:          "DirectEstPath",
			inputPath:     "/v1/pki/est/simpleenroll",
			expectedMount: "pki",
		},
		{
			name:          "CustomMountWellKnown",
			inputPath:     "/v1/pki-prod/.well-known/est/cacerts",
			expectedMount: "pki-prod",
		},
		{
			name:          "CustomMountDirect",
			inputPath:     "/v1/pki-prod/est/cacerts",
			expectedMount: "pki-prod",
		},
		{
			name:          "HyphenatedMount",
			inputPath:     "/v1/pki-test-123/.well-known/est/simplereenroll",
			expectedMount: "pki-test-123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mountPath, err := estMountSegmentFromPath(tc.inputPath)
			if err != nil {
				t.Fatalf("unexpected error extracting mount path: %v", err)
			}
			if mountPath != tc.expectedMount {
				t.Fatalf("expected mount path %q, got %q", tc.expectedMount, mountPath)
			}
		})
	}
}

// TestFindDefaultESTMount tests the findDefaultESTMount function
func TestEstFindDefaultMount(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	core := cluster.Cores[0].Core
	ctx := context.Background()

	t.Run("NoDefaultMount", func(t *testing.T) {
		// Mount PKI without default_mount
		err := client.Sys().Mount("pki1", &api.MountInput{Type: "pki"})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki1/root/generate/internal", map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "87600h",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki1/config/est", map[string]interface{}{
			"enabled":       true,
			"default_mount": false,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Should not find a default mount
		mount, err := findDefaultESTMount(ctx, core)
		if err == nil {
			t.Fatalf("expected error, got mount: %v", mount)
		}
		if !strings.Contains(err.Error(), "no PKI mount found with EST enabled and default_mount=true") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("WithDefaultMount", func(t *testing.T) {
		// Enable default_mount
		_, err := client.Logical().Write("pki1/config/est", map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
		})
		if err != nil {
			t.Fatal(err)
		}

		// Should find the default mount
		mount, err := findDefaultESTMount(ctx, core)
		if err != nil {
			t.Fatalf("expected to find default mount, got error: %v", err)
		}
		if mount.namespacedMountPath() != "pki1" {
			t.Fatalf("expected mount 'pki1', got %q", mount.namespacedMountPath())
		}
	})

	t.Run("MultipleMontsOnlyOneDefault", func(t *testing.T) {
		// Mount second PKI
		err := client.Sys().Mount("pki2", &api.MountInput{Type: "pki"})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki2/root/generate/internal", map[string]interface{}{
			"common_name": "Test CA 2",
			"ttl":         "87600h",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki2/config/est", map[string]interface{}{
			"enabled":       true,
			"default_mount": false,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Should still find pki1 as the default
		mount, err := findDefaultESTMount(ctx, core)
		if err != nil {
			t.Fatalf("expected to find default mount, got error: %v", err)
		}
		if mount.namespacedMountPath() != "pki1" {
			t.Fatalf("expected mount 'pki1', got %q", mount.namespacedMountPath())
		}
	})
}

// TestHandleEstBasicAuthErrors tests error conditions in handleEstBasicAuth
func TestEstBasicAuthErrors(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	ctx := context.Background()
	rootTarget := &estMountTarget{mountPath: "pki", namespace: namespace.RootNamespace}

	t.Run("NilCore", func(t *testing.T) {
		_, err := handleEstBasicAuth(ctx, nil, rootTarget, "user", "pass")
		if err == nil || !strings.Contains(err.Error(), "core is nil") {
			t.Fatalf("expected 'core is nil' error, got: %v", err)
		}
	})

	t.Run("EmptyUsername", func(t *testing.T) {
		_, err := handleEstBasicAuth(ctx, core, rootTarget, "", "pass")
		if err == nil || !strings.Contains(err.Error(), "username and password required") {
			t.Fatalf("expected 'username and password required' error, got: %v", err)
		}
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		_, err := handleEstBasicAuth(ctx, core, rootTarget, "user", "")
		if err == nil || !strings.Contains(err.Error(), "username and password required") {
			t.Fatalf("expected 'username and password required' error, got: %v", err)
		}
	})

	t.Run("NoAuthenticatorsConfigured", func(t *testing.T) {
		client := cluster.Cores[0].Client

		// Setup PKI without authenticators
		err := client.Sys().Mount("pki", &api.MountInput{Type: "pki"})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
			"common_name": "Test CA",
			"ttl":         "87600h",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
			"enabled": true,
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = handleEstBasicAuth(ctx, core, rootTarget, "user", "pass")
		if err == nil || !strings.Contains(err.Error(), "no authenticators configured") {
			t.Fatalf("expected 'no authenticators configured' error, got: %v", err)
		}
	})
}

// Helper functions
// Note: setupPKIForEstTesting and setupUserpassForEst are now in est_test_helpers.go

func getUserpassAccessor(t *testing.T, client *api.Client) string {
	t.Helper()

	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("failed to list auth methods: %v", err)
	}

	for path, auth := range auths {
		if strings.HasPrefix(path, "userpass") {
			return auth.Accessor
		}
	}

	t.Fatal("userpass auth method not found")
	return ""
}

func generateTestCSR(t *testing.T, cn string) []byte {
	csrDER, _ := generateTestCSRWithKey(t, cn)
	return csrDER
}

func generateTestCSRWithKey(t *testing.T, cn string) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames: []string{cn},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	return csrDER, privateKey
}

func estSimpleEnrollWithBasicAuth(t *testing.T, cluster *vault.TestCluster, path, username, password string, csrDER []byte) *x509.Certificate {
	t.Helper()

	resp := estSimpleEnrollRequest(t, cluster, path, username, password, csrDER)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("failed to decode base64 response: %v", err)
	}

	cert, err := parseCertFromPKCS7(decoded)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func estSimpleEnrollRequest(t *testing.T, cluster *vault.TestCluster, path, username, password string, csrDER []byte) *http.Response {
	t.Helper()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{Transport: transport}

	req, err := http.NewRequest("POST", cluster.Cores[0].Client.Address()+path, bytes.NewReader(csrDER))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/pkcs10")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func parseCertFromPKCS7(data []byte) (*x509.Certificate, error) {
	// PKCS#7 OIDs
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// PKCS#7 ContentInfo structure
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}

	// Parse the ContentInfo
	_, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		// If not PKCS#7, try to parse as a raw certificate
		return x509.ParseCertificate(data)
	}

	// Check if it's SignedData
	if !contentInfo.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 ContentInfo is not SignedData")
	}

	// PKCS#7 SignedData structure
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		CRLs             asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos      asn1.RawValue
	}

	// Parse the Content as SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SignedData: %w", err)
	}

	// Extract the first certificate
	if len(signedData.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS#7")
	}

	// Parse the first certificate from the Certificates field
	// The certificates are in a SEQUENCE, each certificate is a SEQUENCE
	var certSeq asn1.RawValue
	rest, err := asn1.Unmarshal(signedData.Certificates.Bytes, &certSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate in PKCS#7: %w", err)
	}

	if len(rest) > 0 {
		// There are more certificates, but we only need the first one for this test
		// In a real implementation, you might want to validate the chain
		fmt.Println("warning: multiple certificates found, using the first one")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certSeq.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return cert, nil
}

func verifyCertificate(t *testing.T, cert *x509.Certificate, expectedCN string) {
	t.Helper()

	if cert.Subject.CommonName != expectedCN {
		t.Fatalf("expected CN %q, got %q", expectedCN, cert.Subject.CommonName)
	}

	if cert.Issuer.CommonName != "EST Test CA" {
		t.Fatalf("expected issuer CN 'EST Test CA', got %q", cert.Issuer.CommonName)
	}
}
