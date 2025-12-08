// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

// Global variables instead of const to allow test cases to overwrite paths.
var (
	// localJWTPath is the path to the Kubernetes Service Account JWT token file.
	localJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// localCACertPath is the path to the Kubernetes API server CA certificate.
	localCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type KubernetesProvider struct {
	// oidcDiscoveryURL is the OIDC discovery URL for the Kubernetes API server.
	oidcDiscoveryURL string
}

func (k *KubernetesProvider) Initialize(_ context.Context, jc *jwtConfig) error {
	// Verify that no conflicting configuration is set.
	if jc.OIDCDiscoveryURL != "" {
		return errors.New("oidc_discovery_url must not be set when using the kubernetes provider")
	}

	if jc.OIDCDiscoveryCAPEM != "" {
		return errors.New("oidc_discovery_ca_pem must not be set when using the kubernetes provider")
	}

	if jc.JWKSURL != "" {
		return errors.New("jwks_url must not be set when using the kubernetes provider")
	}

	if jc.JWKSCAPEM != "" {
		return errors.New("jwks_ca_pem must not be set when using the kubernetes provider")
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

	// Verify that the environment variables are set for the Kubernetes API server address.
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" || os.Getenv("KUBERNETES_SERVICE_PORT") == "" {
		return errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT environment variables must be set when using the kubernetes provider")
	}

	// For security, the OIDC discovery URL is derived from Kubernetes-provided environment variables in the pod,
	// rather than accepting a user-supplied URL.
	k.oidcDiscoveryURL = fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))

	return nil
}

func (k *KubernetesProvider) SensitiveKeys() []string {
	return []string{}
}

func (k *KubernetesProvider) NewKeySet(ctx context.Context) (jwt.KeySet, error) {
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(localCACertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate file: %w", err)
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

	httpClient := &http.Client{
		Transport: saAuthTransport,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	jwksURL, err := retrieveJWKSURL(k.oidcDiscoveryURL+"/.well-known/openid-configuration", ctx, httpClient)
	if err != nil {
		return nil, err
	}

	return jwt.NewJSONWebKeySet(ctx, jwksURL, "")
}

// retrieveJWKSURL fetches the OIDC discovery document from the specified well-known URL and extracts the JWKS URI.
//
// This function is similar to jwt.NewOIDCDiscoveryKeySet(), but it skips validating the "issuer" field:
// this provider relies on Service IP address from KUBERNETES_SERVICE_HOST environment variable on connecting
// the API server, which does not match the issuer field in the discovery document.
func retrieveJWKSURL(wellKnown string, ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", err
	}

	return p.JWKSURL, nil
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
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", strings.TrimSpace(string(token))))
	}
	// If token read fails, proceed without Authorization header.

	return rt.baseTransport.RoundTrip(req)
}
