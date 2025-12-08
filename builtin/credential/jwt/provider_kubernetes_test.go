// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestKubernetesProviderWithOIDCDiscovery(t *testing.T) {
	b, storage := getBackend(t)
	server, token := mockKubernetesAPIServer(t)

	// Configure the backend with OIDC discovery URL and Kubernetes provider.
	// The provider uses the service account token for authentication and the pod CA cert for server validation.
	data := map[string]interface{}{
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Verify that the request to the API server includes Authorization header with the bearer token.
	requests := server.getRequests()
	require.Len(t, requests, 1)
	// First request for OIDC discovery at validation of configuration.
	require.Equal(t, "/.well-known/openid-configuration", requests[0].URL.Path)
	require.Equal(t, "Bearer "+token, requests[0].Header.Get("Authorization"))

	createRole(t, b, storage)

	login(t, b, storage, server.issuerToken("system:serviceaccount:default:openbao-client"))

	requests = server.getRequests()
	require.Len(t, requests, 2)
	// Second request for OIDC discovery when first login occurs.
	require.Equal(t, "/.well-known/openid-configuration", requests[0].URL.Path)
	require.Equal(t, "Bearer "+token, requests[0].Header.Get("Authorization"))
	// Third request for JWKS URI, also at first login.
	require.Equal(t, "/certs", requests[1].URL.Path)
	require.Equal(t, "Bearer "+token, requests[1].Header.Get("Authorization"))

	// Re-attempt login to verify that JWKS caching works and no new request is made to JWKS endpoint.
	login(t, b, storage, server.issuerToken("system:serviceaccount:default:openbao-client"))
	requests = server.getRequests()
	require.Len(t, requests, 0)
}

func TestKubernetesProviderWithJWKSURL(t *testing.T) {
	b, storage := getBackend(t)
	server, token := mockKubernetesAPIServer(t)

	// Configure the backend with JWKS URL and Kubernetes provider.
	// The provider uses the service account token for authentication and the pod CA cert for server validation.
	data := map[string]interface{}{
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	createRole(t, b, storage)

	login(t, b, storage, server.issuerToken("system:serviceaccount:default:openbao-client"))

	// Verify that the request to the API server includes Authorization header with the bearer token.
	requests := server.getRequests()
	require.Len(t, requests, 3)
	// First request for OIDC discovery at validation of configuration.
	require.Equal(t, "/.well-known/openid-configuration", requests[0].URL.Path)
	require.Equal(t, "Bearer "+token, requests[0].Header.Get("Authorization"))
	// Second request for OIDC discovery when first login occurs.
	require.Equal(t, "/.well-known/openid-configuration", requests[1].URL.Path)
	require.Equal(t, "Bearer "+token, requests[1].Header.Get("Authorization"))
	// Third request for JWKS URI, also at first login.
	require.Equal(t, "/certs", requests[2].URL.Path)
	require.Equal(t, "Bearer "+token, requests[2].Header.Get("Authorization"))

	// Re-attempt login to verify that JWKS caching works and no new request are made.
	login(t, b, storage, server.issuerToken("system:serviceaccount:default:openbao-client"))
	requests = server.getRequests()
	require.Len(t, requests, 0)
}

func TestKubernetesProviderWithInvalidConfig(t *testing.T) {
	b, storage := getBackend(t)

	tempDir := t.TempDir()
	caCertPath := path.Join(tempDir, "ca.crt")
	err := os.WriteFile(caCertPath, []byte("test-ca-cert-data"), 0o600)
	require.NoError(t, err)

	// Configure jwks_ca_pem with Kubernetes provider.
	data := map[string]interface{}{
		"jwks_url":    "https://example.com/",
		"jwks_ca_pem": caCertPath,
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// Configure oidc_discovery_ca_pem with Kubernetes provider.
	data = map[string]interface{}{
		"oidc_discovery_url":    "https://example.com/",
		"oidc_discovery_ca_pem": caCertPath,
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestKubernetesProviderWithInvalidTokenFile(t *testing.T) {
	b, storage := getBackend(t)
	server, _ := mockKubernetesAPIServer(t)

	// Overwrite the global SA token path variable to point to a non-existing file.
	localJWTPath = "/non/existing/token/file"

	data := map[string]interface{}{
		"jwks_url": server.server.URL + "/certs",
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestKubernetesProviderWithInvalidCACertFile(t *testing.T) {
	b, storage := getBackend(t)
	server, _ := mockKubernetesAPIServer(t)

	// Overwrite the global CA cert path variable to point to a non-existing file.
	localCACertPath = "/non/existing/ca/cert/file"

	data := map[string]interface{}{
		"jwks_url": server.server.URL + "/certs",
		"provider_config": map[string]interface{}{
			"provider": "kubernetes",
		},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func mockKubernetesAPIServer(t *testing.T) (*oidcProvider, string) {
	t.Helper()

	// Start the test OIDC provider.
	server := newOIDCProvider(t)
	server.clientID = "https://kubernetes.default.svc.cluster.local"
	t.Cleanup(server.server.Close)
	cert, err := server.getTLSCert()
	require.NoError(t, err)

	tempDir := t.TempDir()

	// Write server cert to a file.
	certFile := path.Join(tempDir, "ca.crt")
	err = os.WriteFile(certFile, []byte(cert), 0o600)
	require.NoError(t, err)

	// Write token that will be used to authenticate towards Kubnetes API server.
	tokenFile := path.Join(tempDir, "token")
	token := "my-kubernetes-service-account-token"
	err = os.WriteFile(tokenFile, []byte(token), 0o600)
	require.NoError(t, err)

	// Overwrite the global cert and token variables so that Kubernetes provider uses them instead of the pod paths.
	// This is safe as long as tests are not run in parallel.
	localCACertPath = certFile
	localJWTPath = tokenFile

	parsedURL, _ := url.Parse(server.server.URL)
	os.Setenv("KUBERNETES_SERVICE_HOST", parsedURL.Hostname()) //nolint:errcheck
	os.Setenv("KUBERNETES_SERVICE_PORT", parsedURL.Port())     //nolint:errcheck

	return server, token
}

func createRole(t *testing.T, b logical.Backend, s logical.Storage) {
	t.Helper()

	data := map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_subject":   "system:serviceaccount:default:openbao-client",
		"bound_audiences": "https://kubernetes.default.svc.cluster.local",
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/my-role",
		Storage:   s,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
}

func login(t *testing.T, b logical.Backend, s logical.Storage, jwt string) {
	t.Helper()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   s,
		Data: map[string]interface{}{
			"role": "my-role",
			"jwt":  jwt,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
}
