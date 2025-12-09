package http

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// setupPKIForEstTesting sets up a PKI mount for EST testing with:
// - A root CA
// - Configured URLs
// - A role for EST device enrollment
func setupPKIForEstTesting(t *testing.T, client *api.Client) {
	t.Helper()

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		t.Fatalf("failed to mount pki: %v", err)
	}

	// Generate root CA
	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "EST Test CA",
		"ttl":         "87600h",
	})
	if err != nil {
		t.Fatalf("failed to generate root: %v", err)
	}

	// Configure URLs
	_, err = client.Logical().Write("pki/config/urls", map[string]interface{}{
		"issuing_certificates":    []string{client.Address() + "/v1/pki/ca"},
		"crl_distribution_points": []string{client.Address() + "/v1/pki/crl"},
	})
	if err != nil {
		t.Fatalf("failed to configure URLs: %v", err)
	}

	// Create a role for EST enrollment
	_, err = client.Logical().Write("pki/roles/est-devices", map[string]interface{}{
		"allowed_domains":  []string{"example.com", "iot.local", "devices.local"},
		"allow_subdomains": true,
		"max_ttl":          "720h",
		"key_type":         "rsa",
		"key_bits":         2048,
		"require_cn":       true,
	})
	if err != nil {
		t.Fatalf("failed to create EST role: %v", err)
	}
}

// setupUserpassForEst sets up userpass authentication for EST testing.
// Creates the auth method, a user, and assigns appropriate policies.
func setupUserpassForEst(t *testing.T, client *api.Client, username, password string) {
	t.Helper()

	// Enable userpass
	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatalf("failed to enable userpass: %v", err)
	}

	// Create policy for EST
	policy := `
path "pki/sign-verbatim" {
  capabilities = ["create", "update"]
}
path "pki/sign/*" {
  capabilities = ["create", "update"]
}
path "pki/issue/*" {
  capabilities = ["create", "update"]
}
path "pki/.well-known/est/*" {
  capabilities = ["create", "update"]
}
path "pki/est/*" {
  capabilities = ["create", "update"]
}
`
	err = client.Sys().PutPolicy("est-policy", policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Create user with policy
	_, err = client.Logical().Write("auth/userpass/users/"+username, map[string]interface{}{
		"password": password,
		"policies": []string{"est-policy"},
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
}
