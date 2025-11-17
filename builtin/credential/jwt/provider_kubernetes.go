// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-cleanhttp"
)

// Global variables instead of const to allow test cases to overwrite paths.
var (
	// localJWTPath is the path to the Kubernetes Service Account JWT token file.
	localJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// localCACertPath is the path to the Kubernetes API server CA certificate.
	localCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type KubernetesProvider struct{}

func (k *KubernetesProvider) Initialize(_ context.Context, jc *jwtConfig) error {
	// Ensure JWKSCAPEM and OIDCDiscoveryCAPEM are not set. These options conflict with
	// the Kubernetes provider because they configure a custom HTTP client via github.com/hashicorp/cap
	// when calling jwt.NewJSONWebKeySet() or jwt.NewOIDCDiscoveryKeySet(), preventing
	// the Kubernetes provider from injecting its own HTTP client with proper CA certificate
	// and Authorization header.
	if jc.JWKSCAPEM != "" {
		return errors.New("jwks_ca_pem must not be set when using the kubernetes provider")
	}

	if jc.OIDCDiscoveryCAPEM != "" {
		return errors.New("oidc_discovery_ca_pem must not be set when using the kubernetes provider")
	}

	// Verify that the Service Account token and CA certificate files are accessible.
	_, err := os.ReadFile(localJWTPath)
	if err != nil {
		return fmt.Errorf("error reading service account token file: %w", err)
	}

	_, err = os.ReadFile(localCACertPath)
	if err != nil {
		return fmt.Errorf("error reading CA certificate file: %w", err)
	}

	return nil
}

func (k *KubernetesProvider) SensitiveKeys() []string {
	return []string{}
}

func (k *KubernetesProvider) GetHTTPClient() *http.Client {
	// The HTTP client is created only once by JWT/OIDC authentication method.
	// Note: CA certificate rotation is not supported without restarting or re-creating backend instance.
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(localCACertPath)
	if err != nil {
		return cleanhttp.DefaultPooledClient()
	}

	certPool.AppendCertsFromPEM([]byte(caCert))

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	baseTransport := cleanhttp.DefaultPooledTransport()
	baseTransport.TLSClientConfig = tlsConfig

	saAuthTransport := &bearerAuthRoundTripper{
		baseTransport:      baseTransport,
		kubernetesProvider: k,
	}

	return &http.Client{
		Transport: saAuthTransport,
	}
}

// bearerAuthRoundTripper is an http.RoundTripper that adds an Authorization header
// containing the Kubernetes Service Account token as a bearer token.
type bearerAuthRoundTripper struct {
	baseTransport      http.RoundTripper
	kubernetesProvider *KubernetesProvider
}

func (rt *bearerAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.baseTransport.RoundTrip(req)
	}

	// Clone the request to avoid modifying the original.
	req = req.Clone(req.Context())

	// Read the token from disk on each request.
	// Since discovery and JWKS downloads are infrequent, caching in memory has minimal benefit.
	token, err := os.ReadFile(localJWTPath)
	if err == nil {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	return rt.baseTransport.RoundTrip(req)
}
