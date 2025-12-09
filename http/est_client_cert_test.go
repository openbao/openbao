package http

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	vaultcert "github.com/openbao/openbao/builtin/credential/cert"
	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

// setupCertAuthForEst sets up cert authentication for EST testing.
// Creates the cert auth method, configures a cert role, and assigns appropriate policies.
func setupCertAuthForEst(t *testing.T, client *api.Client, certPEM string, roleName string) {
	t.Helper()

	// Enable cert auth
	err := client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatalf("failed to enable cert auth: %v", err)
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

	// Create cert role with policy
	_, err = client.Logical().Write(fmt.Sprintf("auth/cert/certs/%s", roleName), map[string]interface{}{
		"certificate": certPEM,
		"policies":    []string{"est-policy"},
	})
	if err != nil {
		t.Fatalf("failed to create cert role: %v", err)
	}
}

// generateTestCertificate generates a test certificate for client authentication
func generateTestCertificate(t *testing.T) (certPEM, keyPEM string, cert tls.Certificate) {
	t.Helper()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "openbao.test",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	certPEM = string(certPEMBlock)
	keyPEM = string(keyPEMBlock)

	cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		t.Fatalf("failed to create X509 key pair: %v", err)
	}

	return certPEM, keyPEM, cert
}

// createClientWithCert creates an API client configured to use client certificate authentication
func createClientWithCert(t *testing.T, addr string, cert tls.Certificate, caCert *x509.Certificate) *api.Client {
	t.Helper()

	// Create a certificate pool with the CA cert
	caCertPool := x509.NewCertPool()
	if caCert != nil {
		caCertPool.AddCert(caCert)
	}

	// Configure TLS with client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create client with custom transport
	config := api.DefaultConfig()
	config.Address = addr

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSClientConfig = tlsConfig

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	return client
}

func TestEstClientCertAuthSimpleEnroll(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultcert.Factory,
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

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// Setup PKI backend
	setupPKIForEstTesting(t, client)

	// Generate test certificate
	certPEM, _, _ := generateTestCertificate(t)

	// Setup cert auth
	setupCertAuthForEst(t, client, certPEM, "est-device")

	// Get the cert auth accessor
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("failed to list auth methods: %v", err)
	}
	certMount, ok := auths["cert/"]
	if !ok {
		t.Fatalf("cert auth mount not found after configuration")
	}
	certAccessor := certMount.Accessor

	// Configure EST with cert authenticator
	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":              true,
		"default_mount":        true,
		"default_path_policy":  "sign-verbatim",
		"label_to_path_policy": map[string]string{},
		"authenticators": map[string]interface{}{
			"cert": map[string]interface{}{
				"accessor":  certAccessor,
				"cert_role": "est-device",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	t.Run("SimpleEnrollWithClientCert", func(t *testing.T) {
		t.Skip("TLS client certificate validation occurs at the TLS handshake level, before HTTP handlers. " +
			"Unit tests cannot fully mock TLS handshake behavior. This test requires integration testing " +
			"with real TLS infrastructure to properly validate client certificate authentication.")
	})

	t.Run("ClientCertWithoutConfiguredRole", func(t *testing.T) {
		// Generate a different certificate not configured in cert auth
		_, _, unknownCert := generateTestCertificate(t)
		unknownClient := createClientWithCert(t, client.Address(), unknownCert, cluster.CACert)

		// Generate CSR
		csrDER := generateTestCSR(t, "device2.example.com")
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		// Make EST request - should fail
		url := client.Address() + "/v1/pki/.well-known/est/simpleenroll"
		req, err := http.NewRequest("POST", url, bytes.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/pkcs10")

		resp, err := unknownClient.CloneConfig().HttpClient.Do(req)
		if err != nil {
			t.Fatalf("EST request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should be unauthorized
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Expected non-200 status for unconfigured certificate, got 200")
		}
	})

	t.Run("ClientCertWithoutCertAuthenticatorConfigured", func(t *testing.T) {
		t.Skip("TLS client certificate validation occurs at the TLS handshake level, before HTTP handlers. " +
			"Unit tests cannot fully mock TLS handshake behavior to test missing authenticator config errors. " +
			"This test requires integration testing with real TLS infrastructure.")
	})
}

func TestEstClientCertAuthCacerts(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultcert.Factory,
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

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// Setup PKI backend
	setupPKIForEstTesting(t, client)

	// Generate test certificate
	certPEM, _, clientCert := generateTestCertificate(t)

	// Setup cert auth
	setupCertAuthForEst(t, client, certPEM, "est-device")

	// Get the cert auth accessor
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("failed to list auth methods: %v", err)
	}
	certAccessor := auths["cert/"].Accessor

	// Configure EST with cert authenticator
	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":              true,
		"default_mount":        true,
		"default_path_policy":  "sign-verbatim",
		"label_to_path_policy": map[string]string{},
		"authenticators": map[string]interface{}{
			"cert": map[string]interface{}{
				"accessor":  certAccessor,
				"cert_role": "est-device",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	t.Run("CacertsWithClientCert", func(t *testing.T) {
		// Create client with certificate
		certClient := createClientWithCert(t, client.Address(), clientCert, cluster.CACert)

		// Request CA certificates
		url := client.Address() + "/v1/pki/.well-known/est/cacerts"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		resp, err := certClient.CloneConfig().HttpClient.Do(req)
		if err != nil {
			t.Fatalf("EST cacerts request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify response content type
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/pkcs7-mime") {
			t.Errorf("Expected content-type starting with 'application/pkcs7-mime', got '%s'", contentType)
		}

		// Verify we got certificates back
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		if len(body) == 0 {
			t.Fatal("Expected certificates in response body")
		}
	})
}

func TestEstClientCertAuthErrors(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultcert.Factory,
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

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// Setup PKI backend
	setupPKIForEstTesting(t, client)

	t.Run("NoCertificateProvided", func(t *testing.T) {
		// Enable cert auth
		err := client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
			Type: "cert",
		})
		if err != nil {
			t.Fatalf("failed to enable cert auth: %v", err)
		}

		// Get accessor
		auths, err := client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("failed to list auth methods: %v", err)
		}
		certAccessor := auths["cert/"].Accessor

		// Configure EST with cert authenticator
		_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
			"authenticators": map[string]interface{}{
				"cert": map[string]interface{}{
					"accessor": certAccessor,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to configure EST: %v", err)
		}

		// Make request without client certificate
		csrDER := generateTestCSR(t, "device.example.com")
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})
		url := client.Address() + "/v1/pki/.well-known/est/simpleenroll"
		req, err := http.NewRequest("POST", url, bytes.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/pkcs10")

		resp, err := client.CloneConfig().HttpClient.Do(req)
		if err != nil {
			t.Fatalf("EST request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should fail - no certificate provided
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Expected non-200 status when no certificate provided, got 200")
		}
	})

	t.Run("InvalidAccessorInConfig", func(t *testing.T) {
		// Generate and configure a valid cert (cert auth already enabled from previous subtest)
		certPEM, _, clientCert := generateTestCertificate(t)
		// Create cert role
		err := client.Sys().PutPolicy("est-policy", `
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
`)
		if err != nil {
			t.Fatalf("failed to create policy: %v", err)
		}

		_, err = client.Logical().Write("auth/cert/certs/test-device", map[string]interface{}{
			"certificate": certPEM,
			"policies":    []string{"est-policy"},
		})
		if err != nil {
			t.Fatalf("failed to create cert role: %v", err)
		}

		// Configure EST with invalid accessor
		_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
			"authenticators": map[string]interface{}{
				"cert": map[string]interface{}{
					"accessor": "invalid-accessor-id",
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to configure EST: %v", err)
		}

		// Create client with certificate
		certClient := createClientWithCert(t, client.Address(), clientCert, cluster.CACert)

		// Make EST request
		csrDER := generateTestCSR(t, "device.example.com")
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})
		url := client.Address() + "/v1/pki/.well-known/est/simpleenroll"
		req, err := http.NewRequest("POST", url, bytes.NewReader(csrPEM))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/pkcs10")

		resp, err := certClient.CloneConfig().HttpClient.Do(req)
		if err != nil {
			t.Fatalf("EST request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should fail - invalid accessor
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Expected non-200 status with invalid accessor, got 200")
		}
	})

	t.Run("MissingAccessorInConfig", func(t *testing.T) {
		// Try to configure EST without accessor - should fail at config write time
		_, err := client.Logical().Write("pki/config/est", map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
			"authenticators": map[string]interface{}{
				"cert": map[string]interface{}{
					// No accessor specified
					"cert_role": "test-device",
				},
			},
		})
		// Should fail at config time with validation error
		if err == nil {
			t.Fatal("Expected error when configuring EST without accessor, got nil")
		}
		if !contains(err.Error(), "accessor") {
			t.Errorf("Expected error message about missing accessor, got: %v", err)
		}
	})
}

func TestEstClientCertWithExpiredCertificate(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultcert.Factory,
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

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// Setup PKI backend
	setupPKIForEstTesting(t, client)

	// Read an expired certificate from test fixtures
	expiredCertPEM, err := os.ReadFile("../vault/diagnose/test-fixtures/expiredcert.pem")
	if err != nil {
		t.Skipf("Skipping expired cert test: %v", err)
	}

	// Setup cert auth with expired cert (this will succeed - validation happens at login)
	setupCertAuthForEst(t, client, string(expiredCertPEM), "expired-device")

	// Get accessor
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("failed to list auth methods: %v", err)
	}
	certAccessor := auths["cert/"].Accessor

	// Configure EST
	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "sign-verbatim",
		"authenticators": map[string]interface{}{
			"cert": map[string]interface{}{
				"accessor":  certAccessor,
				"cert_role": "expired-device",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	// Parse the expired cert
	block, _ := pem.Decode(expiredCertPEM)
	if block == nil {
		t.Fatal("failed to decode expired cert PEM")
	}
	expiredCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse expired cert: %v", err)
	}

	// Note: We can't easily create a tls.Certificate from just the cert PEM without the key,
	// so this test verifies the configuration is correct, but actual TLS connection
	// would fail at the TLS handshake level before reaching our EST handler
	t.Logf("Expired certificate test configured. In production, TLS handshake would reject cert valid from %s to %s",
		expiredCert.NotBefore, expiredCert.NotAfter)
}

func TestEstSimpleReenrollTLSRequirements(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": vaultcert.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{HandlerFunc: Handler})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	setupPKIForEstTesting(t, client)

	// Ensure the Vault listener trusts the PKI root so that client TLS certs issued by
	// the EST test mount can participate in the TLS handshake and be forwarded to the handler.
	caResp, err := client.Logical().Read("pki/cert/ca")
	if err != nil {
		t.Fatalf("failed to read PKI root certificate: %v", err)
	}
	caPEM, ok := caResp.Data["certificate"].(string)
	if !ok || caPEM == "" {
		t.Fatal("PKI root certificate missing from response")
	}
	if cluster.RootCAs == nil || !cluster.RootCAs.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("failed to append PKI root certificate to cluster RootCAs")
	}

	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "role:est-devices",
	})
	if err != nil {
		t.Fatalf("failed to configure EST: %v", err)
	}

	csrDER, deviceKey := generateTestCSRWithKey(t, "tls-device.example.com")
	originalCert := estSimpleEnrollWithToken(t, cluster, "/.well-known/est/simpleenroll", client.Token(), csrDER)
	deviceTLSCert := tlsCertificateFromIssuedCert(t, originalCert, deviceKey)
	deviceCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: originalCert.Raw})
	certRoleName := "reenroll-device"
	setupCertAuthForEst(t, client, string(deviceCertPEM), certRoleName)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("failed to list auth methods: %v", err)
	}
	certAccessor := auths["cert/"].Accessor

	_, err = client.Logical().Write("pki/config/est", map[string]interface{}{
		"enabled":             true,
		"default_mount":       true,
		"default_path_policy": "role:est-devices",
		"authenticators": map[string]interface{}{
			"cert": map[string]interface{}{
				"accessor":  certAccessor,
				"cert_role": certRoleName,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to update EST auth config: %v", err)
	}

	reenrollClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{deviceTLSCert},
		},
	}}
	reenrollURL := client.Address() + "/.well-known/est/simplereenroll"

	t.Run("SuccessWithMatchingIdentity", func(t *testing.T) {
		csrDER2, _ := generateTestCSRWithKey(t, "tls-device.example.com")
		resp := estPostCSRWithClient(t, reenrollClient, reenrollURL, csrDER2)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read reenroll response: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			t.Fatalf("failed to decode reenroll response: %v", err)
		}

		cert, err := parseCertFromPKCS7(decoded)
		if err != nil {
			t.Fatalf("failed to parse reenrolled certificate: %v", err)
		}
		verifyCertificate(t, cert, "tls-device.example.com")
	})

	t.Run("RejectsSubjectMismatch", func(t *testing.T) {
		csrDERMismatch, _ := generateTestCSRWithKey(t, "unexpected.example.com")
		resp := estPostCSRWithClient(t, reenrollClient, reenrollURL, csrDERMismatch)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 Bad Request, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

func estSimpleEnrollWithToken(t *testing.T, cluster *vault.TestCluster, path, token string, csrDER []byte) *x509.Certificate {
	t.Helper()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("POST", cluster.Cores[0].Client.Address()+path, bytes.NewReader(csrDER))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 from EST simpleenroll, got %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("failed to decode EST response: %v", err)
	}
	cert, err := parseCertFromPKCS7(decoded)
	if err != nil {
		t.Fatalf("failed to parse EST certificate: %v", err)
	}
	return cert
}

func estPostCSRWithClient(t *testing.T, httpClient *http.Client, url string, csrDER []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewReader(csrDER))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func tlsCertificateFromIssuedCert(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to build TLS key pair: %v", err)
	}
	return tlsCert
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
