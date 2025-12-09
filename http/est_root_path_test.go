// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

// TestEstRootPathWithDefaultMount tests that EST endpoints are accessible
// at the root /.well-known/est/ path when default_mount is enabled
func TestEstRootPathWithDefaultMount(t *testing.T) {
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

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatalf("failed to mount pki: %v", err)
	}

	// Generate root CA
	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "Root CA",
		"ttl":         "87600h",
	})
	if err != nil {
		t.Fatalf("failed to generate root: %v", err)
	}

	// Enable EST with default_mount
	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	// Test root path: /.well-known/est/cacerts
	testRootEstPath(t, cluster, "/.well-known/est/cacerts")

	// Also test that the regular mount path still works
	testRootEstPath(t, cluster, "/v1/pki/.well-known/est/cacerts")
}

// TestEstRootPathWithoutDefaultMount tests that root paths return 404
// when default_mount is not enabled
func TestEstRootPathWithoutDefaultMount(t *testing.T) {
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

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatalf("failed to mount pki: %v", err)
	}

	// Generate root CA
	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "Root CA",
		"ttl":         "87600h",
	})
	if err != nil {
		t.Fatalf("failed to generate root: %v", err)
	}

	// Enable EST but WITHOUT default_mount
	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       false,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	// Test that root path returns 404
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", cluster.Cores[0].Client.Address()+"/.well-known/est/cacerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", client.Token())

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should get 404 since default_mount is not enabled
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	// But the regular mount path should still work
	testRootEstPath(t, cluster, "/v1/pki/.well-known/est/cacerts")
}

// TestEstRootPathMultipleMounts tests that only one mount can have default_mount enabled
func TestEstRootPathMultipleMounts(t *testing.T) {
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

	// Mount first PKI
	err := client.Sys().Mount("pki1", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatalf("failed to mount pki1: %v", err)
	}

	// Generate root CA for pki1
	_, err = client.Logical().Write("pki1/root/generate/internal", map[string]interface{}{
		"common_name": "Root CA 1",
		"ttl":         "87600h",
	})
	if err != nil {
		t.Fatalf("failed to generate root for pki1: %v", err)
	}

	// Enable EST with default_mount on pki1
	_, err = client.Logical().Write("pki1/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to configure EST for pki1: %v", err)
	}

	// Mount second PKI
	err = client.Sys().Mount("pki2", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatalf("failed to mount pki2: %v", err)
	}

	// Generate root CA for pki2
	_, err = client.Logical().Write("pki2/root/generate/internal", map[string]interface{}{
		"common_name": "Root CA 2",
		"ttl":         "87600h",
	})
	if err != nil {
		t.Fatalf("failed to generate root for pki2: %v", err)
	}

	// Try to enable EST with default_mount on pki2 - should succeed at write time
	// but fail when the root path is actually accessed
	_, err = client.Logical().Write("pki2/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to enable EST on pki2: %v", err)
	}

	// Now try to access the root EST path - should fail because multiple mounts have default_mount=true
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", cluster.Cores[0].Client.Address()+"/.well-known/est/cacerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", client.Token())

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404 when accessing root EST path with multiple default mounts, got %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "multiple PKI mounts") || !strings.Contains(bodyStr, "default_mount") {
		t.Fatalf("expected error about multiple default mounts, got: %s", bodyStr)
	}

	// Disable default_mount on pki2
	_, err = client.Logical().Write("pki2/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       false,
		"default_path_policy": "sign-verbatim",
	})
	if err != nil {
		t.Fatalf("failed to disable default_mount on pki2: %v", err)
	}

	// Root path should now work again with pki1
	testRootEstPath(t, cluster, "/.well-known/est/cacerts")
}

// testRootEstPath is a helper function to test EST cacerts endpoint
func testRootEstPath(t *testing.T, cluster *vault.TestCluster, path string) {
	client := cluster.Cores[0].Client

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", cluster.Cores[0].Client.Address()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", client.Token())

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/pkcs7-mime" && contentType != "application/pkcs7-mime; smime-type=certs-only" {
		t.Fatalf("unexpected content type: %s", contentType)
	}

	// Read and verify response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(body) == 0 {
		t.Fatal("empty response body")
	}

	// The response should be base64-encoded PKCS#7
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("failed to decode base64 response: %v", err)
	}

	if len(decoded) == 0 {
		t.Fatal("empty decoded response")
	}
}
