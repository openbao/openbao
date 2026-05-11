// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-sockaddr"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"golang.org/x/net/http2"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/helper/namespace"
	logicaltest "github.com/openbao/openbao/helper/testhelpers/logical"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

type testCerts struct {
	exampleCA   *certyaml.Certificate
	exampleCert *certyaml.Certificate
	clientCA    *certyaml.Certificate
	clientCert  *certyaml.Certificate
	client2CA   *certyaml.Certificate
	client2Cert *certyaml.Certificate
}

func setupTestCerts(t *testing.T) *testCerts {
	t.Helper()

	tc := &testCerts{}

	tc.exampleCA = &certyaml.Certificate{
		Subject:         "cn=ca.example.com",
		SubjectAltNames: []string{"DNS:ca.example.com", "IP:127.0.0.1"},
	}
	tc.exampleCert = &certyaml.Certificate{
		Subject:         "cn=cert.example.com",
		SubjectAltNames: []string{"DNS:cert.example.com", "IP:127.0.0.1"},
		Issuer:          tc.exampleCA,
	}

	tc.clientCA = &certyaml.Certificate{
		Subject:         "cn=ca1.openbao.org",
		SubjectAltNames: []string{"DNS:ca1.openbao.org"},
	}
	tc.clientCert = &certyaml.Certificate{
		Subject:         "cn=client.ca1.openbao.org",
		SubjectAltNames: []string{"DNS:client.ca1.openbao.org"},
		Issuer:          tc.clientCA,
	}

	tc.client2CA = &certyaml.Certificate{
		Subject:         "cn=ca2.openbao.org",
		SubjectAltNames: []string{"DNS:ca2.openbao.org"},
	}
	tc.client2Cert = &certyaml.Certificate{
		Subject:         "cn=client.ca2.openbao.org",
		SubjectAltNames: []string{"DNS:client.ca2.openbao.org"},
		Issuer:          tc.client2CA,
	}

	return tc
}

// Unlike testConnState, this method does not use the same 'tls.Config' objects for
// both dialing and listening. Instead, it runs the server without specifying its CA.
// But the client, presents the CA cert of the server to trust the server.
// The client can present a cert and key which is completely independent of server's CA.
// The connection state returned will contain the certificate presented by the client.
func connectionState(serverCA, serverCert, clientCert *certyaml.Certificate) (tls.ConnectionState, error) {
	serverKeyPair, err := serverCert.TLSCertificate()
	if err != nil {
		return tls.ConnectionState{}, err
	}
	// Prepare the listener configuration with server's key pair
	listenConf := &tls.Config{
		Certificates: []tls.Certificate{serverKeyPair},
		ClientAuth:   tls.RequestClientCert,
	}

	clientKeyPair, err := clientCert.TLSCertificate()
	if err != nil {
		return tls.ConnectionState{}, err
	}
	serverCACert, err := serverCA.X509Certificate()
	if err != nil {
		return tls.ConnectionState{}, err
	}

	// Initialize the cert pool.
	serverCAs := x509.NewCertPool()
	serverCAs.AddCert(&serverCACert)

	// Prepare the dial configuration that the client uses to establish the connection.
	dialConf := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      serverCAs,
	}

	// Start the server.
	list, err := tls.Listen("tcp", "127.0.0.1:0", listenConf)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer list.Close() //nolint:errcheck // try to close, ignore error

	// Accept connections.
	serverErrors := make(chan error, 1)
	connState := make(chan tls.ConnectionState)
	go func() {
		defer close(connState)
		serverConn, err := list.Accept()
		if err != nil {
			serverErrors <- err
			close(serverErrors)
			return
		}
		defer serverConn.Close() //nolint:errcheck // try to close, ignore error

		// Read the ping
		buf := make([]byte, 4)
		_, err = serverConn.Read(buf)
		if (err != nil) && (err != io.EOF) {
			serverErrors <- err
			close(serverErrors)
			return
		}
		close(serverErrors)
		connState <- serverConn.(*tls.Conn).ConnectionState()
	}()

	// Establish a connection from the client side and write a few bytes.
	clientErrors := make(chan error, 1)
	go func() {
		addr := list.Addr().String()
		conn, err := tls.Dial("tcp", addr, dialConf)
		if err != nil {
			clientErrors <- err
			close(clientErrors)
			return
		}
		defer conn.Close()

		// Write ping
		_, err = conn.Write([]byte("ping"))
		if err != nil {
			clientErrors <- err
		}
		close(clientErrors)
	}()

	for err = range clientErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in client goroutine:%v", err)
		}
	}

	for err = range serverErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in server goroutine:%v", err)
		}
	}
	// Grab the current state
	return <-connState, nil
}

func TestBackend_PermittedDNSDomainsIntermediateCA(t *testing.T) {
	// Enable PKI secret engine and Cert auth method
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Mount /pki as a root CA
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the cluster's certificate as the root CA in /pki
	pemBundleRootCA := string(cluster.CACertPEM) + string(cluster.CAKeyPEM)
	_, err = client.Logical().Write("pki/config/ca", map[string]interface{}{
		"pem_bundle": pemBundleRootCA,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mount /pki2 to operate as an intermediate CA
	err = client.Sys().Mount("pki2", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a CSR for the intermediate CA
	secret, err := client.Logical().Write("pki2/intermediate/generate/internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCSR := secret.Data["csr"].(string)

	// Sign the intermediate CSR using /pki
	secret, err = client.Logical().Write("pki/root/sign-intermediate", map[string]interface{}{
		"permitted_dns_domains": ".example.com",
		"csr":                   intermediateCSR,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediateCertPEM := secret.Data["certificate"].(string)

	// Configure the intermediate cert as the CA in /pki2
	_, err = client.Logical().Write("pki2/intermediate/set-signed", map[string]interface{}{
		"certificate": intermediateCertPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a role on the intermediate CA mount
	_, err = client.Logical().Write("pki2/roles/openbao-cert", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": "true",
		"max_ttl":          "5m",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Issue a leaf cert using the intermediate CA
	secret, err = client.Logical().Write("pki2/issue/openbao-cert", map[string]interface{}{
		"common_name": "cert.example.com",
		"format":      "pem",
		"ip_sans":     "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	leafCertPEM := secret.Data["certificate"].(string)
	leafCertKeyPEM := secret.Data["private_key"].(string)

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the intermediate CA cert as a trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/openbao-cert", map[string]interface{}{
		"display_name": "example.com",
		"policies":     "default",
		"certificate":  intermediateCertPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create temporary files for CA cert, client cert and client cert key.
	// This is used to configure TLS in the api client.
	tempDir := t.TempDir()
	caCertFile := filepath.Join(tempDir, "ca.pem")
	require.NoError(t, os.WriteFile(caCertFile, []byte(cluster.CACertPEM), 0o600))
	leafCertFile := filepath.Join(tempDir, "leaf.pem")
	require.NoError(t, os.WriteFile(leafCertFile, []byte(leafCertPEM), 0o600))
	leafCertKeyFile := filepath.Join(tempDir, "leaf-key.pem")
	require.NoError(t, os.WriteFile(leafCertKeyFile, []byte(leafCertKeyPEM), 0o600))

	// This function is a copy-pasta from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with the leaf
	// certificate generated above.
	getAPIClient := func(port int, tlsConfig *tls.Config) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return errors.New("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the above issued certificates as the client certificates
		err := config.ConfigureTLS(&api.TLSConfig{
			CACert:     caCertFile,
			ClientCert: leafCertFile,
			ClientKey:  leafCertKeyFile,
		})
		if err != nil {
			t.Fatal(err)
		}

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the desired TLS configuration
	newClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig())

	secret, err = newClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "openbao-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatal("expected a successful authentication")
	}

	// testing pathLoginRenew for cert auth
	oldAccessor := secret.Auth.Accessor
	newClient.SetToken(client.Token())
	secret, err = newClient.Logical().Write("auth/token/renew-accessor", map[string]interface{}{
		"accessor":  secret.Auth.Accessor,
		"increment": 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	if secret.Auth == nil || secret.Auth.ClientToken != "" || secret.Auth.LeaseDuration != 3600 || secret.Auth.Accessor != oldAccessor {
		t.Fatal("unexpected accessor renewal")
	}
}

func TestBackend_MetadataBasedACLPolicy(t *testing.T) {
	tc := setupTestCerts(t)

	extValue1, _ := asn1.Marshal("A UTF8String Extension")
	extCert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"IP:127.0.0.1", "email:valid@example.com"},
		Issuer:          tc.exampleCA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 1, 1, 1},
				Value: extValue1,
			},
		},
	}
	tempDir := t.TempDir()
	exCertFile := filepath.Join(tempDir, "extcert.pem")
	exCertKeyFile := filepath.Join(tempDir, "extcert-key.pem")
	require.NoError(t, extCert.WritePEM(exCertFile, exCertKeyFile))

	// Start cluster with cert auth method enabled
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Enable metadata in aliases
	_, err = client.Logical().Write("auth/cert/config", map[string]interface{}{
		"enable_identity_alias_metadata": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve its accessor id
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var accessor string

	for _, auth := range auths {
		if auth.Type == "cert" {
			accessor = auth.Accessor
		}
	}

	if accessor == "" {
		t.Fatal("failed to find cert auth accessor")
	}

	// Write ACL policy
	err = client.Sys().PutPolicy("metadata-based", fmt.Sprintf(`
path "kv/cn/{{identity.entity.aliases.%s.metadata.common_name}}" {
	capabilities = ["read"]
}
path "kv/ext/{{identity.entity.aliases.%s.metadata.2-1-1-1}}" {
	capabilities = ["read"]
}
`, accessor, accessor))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Set the trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/test", map[string]interface{}{
		"display_name":                "test",
		"policies":                    "metadata-based",
		"certificate":                 string(tc.exampleCA.CertPEM()),
		"allowed_metadata_extensions": "2.1.1.1,1.2.3.45",
	})
	if err != nil {
		t.Fatal(err)
	}

	// This function is a copy-paste from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with a
	// specific client certificate.
	getAPIClient := func(port int, tlsConfig *tls.Config) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return errors.New("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the client certificates
		err := config.ConfigureTLS(&api.TLSConfig{
			CACertBytes: cluster.CACertPEM,
			ClientCert:  exCertFile,
			ClientKey:   exCertKeyFile,
		})
		if err != nil {
			t.Fatal(err)
		}

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the desired TLS configuration
	newClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig())

	var secret *api.Secret

	secret, err = newClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatal("expected a successful authentication")
	}

	// Check paths guarded by ACL policy
	newClient.SetToken(secret.Auth.ClientToken)

	_, err = newClient.Logical().Read("kv/cn/example.com")
	if err != nil {
		t.Fatal(err)
	}

	_, err = newClient.Logical().Read("kv/cn/not.example.com")
	if err == nil {
		t.Fatal("expected access denied")
	}

	_, err = newClient.Logical().Read("kv/ext/A UTF8String Extension")
	if err != nil {
		t.Fatal(err)
	}

	_, err = newClient.Logical().Read("kv/ext/bar")
	if err == nil {
		t.Fatal("expected access denied")
	}
}

func TestBackend_NonCAExpiry(t *testing.T) {
	var resp *logical.Response
	var err error

	// Create CA and issue a short-lived leaf certificate.
	shortExpiry := 3 * time.Second
	ca := &certyaml.Certificate{
		Subject:         "cn=localhost",
		SubjectAltNames: []string{"IP:127.0.0.1"},
	}
	issuedCert := &certyaml.Certificate{
		Subject: "cn=localhost",
		Issuer:  ca,
		Expires: &shortExpiry,
	}

	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Register the Non-CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  issuedCert.CertPEM(),
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}
	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err = b.HandleRequest(t.Context(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Create connection state using the certificates generated
	connState, err := connectionState(ca, ca, issuedCert)
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}

	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}

	// Login when the certificate is still valid. Login should succeed.
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Wait until the certificate expires
	time.Sleep(5 * time.Second)

	// Login attempt after certificate expiry should fail
	_, err = b.HandleRequest(t.Context(), loginReq)
	if err == nil {
		t.Fatal("expected error due to expired certificate")
	}
}

func TestBackend_RegisteredNonCA_CRL(t *testing.T) {
	tc := setupTestCerts(t)
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Register the Non-CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  tc.clientCert.CertPEM(),
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}
	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err := b.HandleRequest(t.Context(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Connection state is presenting the client Non-CA cert and its key.
	// This is exactly what is registered at the backend.
	connState, err := connectionState(tc.exampleCA, tc.exampleCert, tc.clientCert)
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}
	// Login should succeed.
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the issued client certificate used above.
	crl := &certyaml.CRL{
		Issuer:  tc.clientCA,
		Revoked: []*certyaml.Certificate{tc.clientCert},
	}
	issuedCRL, _ := crl.PEM()

	crlData := map[string]interface{}{
		"crl": issuedCRL,
	}
	crlReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "crls/issuedcrl",
		Data:      crlData,
	}
	resp, err = b.HandleRequest(t.Context(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Ensure the CRL shows up on a list.
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "crls",
		Data:      map[string]interface{}{},
	}
	resp, err = b.HandleRequest(t.Context(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if len(resp.Data) != 1 || len(resp.Data["keys"].([]string)) != 1 || resp.Data["keys"].([]string)[0] != "issuedcrl" {
		t.Fatalf("bad listing: resp:%v", resp)
	}

	// Attempt login with the same connection state but with the CRL registered
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected failure due to revoked certificate")
	}
}

func TestBackend_CRLs(t *testing.T) {
	tc := setupTestCerts(t)
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Register the CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  tc.clientCA.CertPEM(),
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}

	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err := b.HandleRequest(t.Context(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Connection state is presenting the client CA cert and its key.
	// This is exactly what is registered at the backend.
	connState, err := connectionState(tc.exampleCA, tc.exampleCert, tc.clientCA)
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Now, without changing the registered client CA cert, present from
	// the client side, a cert issued using the registered CA.
	connState, err = connectionState(tc.exampleCA, tc.exampleCert, tc.clientCert)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	loginReq.Connection = &logical.Connection{
		ConnState: &connState,
	}

	// Attempt login with the updated connection
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the issued client certificate used above.
	crl := &certyaml.CRL{
		Issuer:  tc.clientCA,
		Revoked: []*certyaml.Certificate{tc.clientCert},
	}
	issuedCRL, _ := crl.PEM()

	crlData := map[string]interface{}{
		"crl": issuedCRL,
	}

	crlReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "crls/issuedcrl",
		Data:      crlData,
	}
	resp, err = b.HandleRequest(t.Context(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Attempt login with the revoked certificate.
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected failure due to revoked certificate")
	}

	// Register a different client CA certificate.
	certData["certificate"] = tc.client2CA.CertPEM()
	resp, err = b.HandleRequest(t.Context(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Test login using a different client CA cert pair.
	connState, err = connectionState(tc.exampleCA, tc.exampleCert, tc.client2Cert)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	loginReq.Connection = &logical.Connection{
		ConnState: &connState,
	}

	// Attempt login with the updated connection
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the client certificate used above.
	rootCRL := &certyaml.CRL{
		Issuer:  tc.client2CA,
		Revoked: []*certyaml.Certificate{tc.client2Cert},
	}
	rootCRLPEM, _ := rootCRL.PEM()
	crlData["crl"] = rootCRLPEM
	resp, err = b.HandleRequest(t.Context(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Attempt login with the same connection state but with the CRL registered
	resp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected failure due to revoked certificate")
	}
}

func testFactory(t *testing.T) logical.Backend {
	storage := &logical.InmemStorage{}
	ctx := namespace.RootContext(t.Context())
	b, err := Factory(ctx, &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 1000 * time.Second,
			MaxLeaseTTLVal:     1800 * time.Second,
		},
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if err := b.Initialize(ctx, &logical.InitializationRequest{
		Storage: storage,
	}); err != nil {
		t.Fatalf("error: %s", err)
	}
	return b
}

// Test the certificates being registered to the backend
func TestBackend_CertWrites(t *testing.T) {
	tc := setupTestCerts(t)

	// Non CA cert without TLS web client authentication
	noClientAuthCert := &certyaml.Certificate{
		Subject:         "cn=noclientauth",
		SubjectAltNames: []string{"IP:127.0.0.1"},
		Issuer:          tc.exampleCA,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	testCase := logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "aaa", tc.exampleCA.CertPEM(), "foo", allowed{}, false),
			testAccStepCert(t, "bbb", tc.exampleCert.CertPEM(), "foo", allowed{}, false),
			testAccStepCert(t, "ccc", noClientAuthCert.CertPEM(), "foo", allowed{}, true),
		},
	}
	testCase.Steps = append(testCase.Steps, testAccStepListCerts(t, []string{"aaa", "bbb"})...)
	logicaltest.Test(t, testCase)
}

// Test a client trusted by a CA
func TestBackend_basic_CA(t *testing.T) {
	tc := setupTestCerts(t)

	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCertLease(t, "web", tc.exampleCA.CertPEM(), "foo"),
			testAccStepCertTTL(t, "web", tc.exampleCA.CertPEM(), "foo"),
			testAccStepLogin(t, connState),
			testAccStepCertMaxTTL(t, "web", tc.exampleCA.CertPEM(), "foo"),
			testAccStepLogin(t, connState),
			testAccStepCertNoLease(t, "web", tc.exampleCA.CertPEM(), "foo"),
			testAccStepLoginDefaultLease(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{names: "*.example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{names: "*.invalid.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test CRL behavior
func TestBackend_Basic_CRLs(t *testing.T) {
	tc := setupTestCerts(t)

	crl := &certyaml.CRL{
		Issuer:  tc.exampleCA,
		Revoked: []*certyaml.Certificate{tc.exampleCert},
	}
	crlPEM, _ := crl.PEM()

	cert, _ := tc.exampleCert.X509Certificate()

	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCertNoLease(t, "web", tc.exampleCA.CertPEM(), "foo"),
			testAccStepLoginDefaultLease(t, connState),
			testAccStepAddCRL(t, crlPEM, connState),
			testAccStepReadCRL(t, connState, cert.SerialNumber.String()),
			testAccStepLoginInvalid(t, connState),
			testAccStepDeleteCRL(t, connState),
			testAccStepLoginDefaultLease(t, connState),
		},
	})
}

// Test a self-signed client (root CA) that is trusted
func TestBackend_basic_singleCert(t *testing.T) {
	tc := setupTestCerts(t)
	connState, err := testConnState(tc.exampleCA, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{names: "ca.example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{names: "invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{ext: "1.2.3.4:invalid"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

func TestBackend_common_name_singleCert(t *testing.T) {
	tc := setupTestCerts(t)
	connState, err := testConnState(tc.exampleCA, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{common_names: "ca.example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{common_names: "invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", tc.exampleCA.CertPEM(), "foo", allowed{ext: "1.2.3.4:invalid"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with custom ext (root CA) that is trusted
func TestBackend_ext_singleCert(t *testing.T) {
	tc := setupTestCerts(t)

	// Create certificate with custom extensions.
	extValue1, _ := asn1.Marshal("A UTF8String Extension")
	extValue2, _ := asn1.Marshal("A UTF8String Extension 2")
	extCert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"IP:127.0.0.1"},
		Issuer:          tc.exampleCA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 1, 1, 1},
				Value: extValue1,
			},
			{
				Id:    asn1.ObjectIdentifier{2, 1, 1, 2},
				Value: extValue2,
			},
		},
	}
	connState, err := testConnState(extCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca := tc.exampleCA.CertPEM()
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:,2.1.1.2:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepReadConfig(t, config{EnableIdentityAliasMetadata: false}, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "2.1.1.1,1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{"2-1-1-1": "A UTF8String Extension"}, false),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{}, false),
			testAccStepSetConfig(t, config{EnableIdentityAliasMetadata: true}, connState),
			testAccStepReadConfig(t, config{EnableIdentityAliasMetadata: true}, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "2.1.1.1,1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{"2-1-1-1": "A UTF8String Extension"}, true),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{}, true),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_dns_singleCert(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"DNS:example.com", "IP:127.0.0.1"},
		Issuer:          ca,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "*ample.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "notincert.com"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "*.example.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_email_singleCert(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"email:valid@example.com", "IP:127.0.0.1"},
		Issuer:          ca,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{emails: "valid@example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{emails: "*@example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{emails: "invalid@notincert.com"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{emails: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{emails: "*.example.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with OU (root CA) that is trusted
func TestBackend_organizationalUnit_singleCert(t *testing.T) {
	cert := &certyaml.Certificate{
		Subject:         "cn=example.com,ou=engineering",
		SubjectAltNames: []string{"IP:127.0.0.1"},
	}
	connState, err := testConnState(cert, cert)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", cert.CertPEM(), "foo", allowed{organizational_units: "engineering"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", cert.CertPEM(), "foo", allowed{organizational_units: "eng*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", cert.CertPEM(), "foo", allowed{organizational_units: "engineering,finance"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", cert.CertPEM(), "foo", allowed{organizational_units: "foo"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_uri_singleCert(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"IP:127.0.0.1", "URI:spiffe://example.com/host"},
		Issuer:          ca,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{uris: "spiffe://example.com/*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{uris: "spiffe://example.com/host"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{uris: "spiffe://example.com/invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{uris: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{uris: "http://www.google.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test against a collection of matching and non-matching rules
func TestBackend_mixed_constraints(t *testing.T) {
	tc := setupTestCerts(t)
	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "1unconstrained", tc.exampleCA.CertPEM(), "foo", allowed{}, false),
			testAccStepCert(t, "2matching", tc.exampleCA.CertPEM(), "foo", allowed{names: "*.example.com,whatever"}, false),
			testAccStepCert(t, "3invalid", tc.exampleCA.CertPEM(), "foo", allowed{names: "invalid"}, false),
			testAccStepLogin(t, connState),
			// Assumes CertEntries are processed in alphabetical order (due to store.List), so we only match 2matching if 1unconstrained doesn't match
			testAccStepLoginWithName(t, connState, "2matching"),
			testAccStepLoginWithNameInvalid(t, connState, "3invalid"),
		},
	})
}

// Test an untrusted client
func TestBackend_untrusted(t *testing.T) {
	tc := setupTestCerts(t)
	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepLoginInvalid(t, connState),
		},
	})
}

func TestBackend_validCIDR(t *testing.T) {
	tc := setupTestCerts(t)
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}

	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	name := "web"
	boundCIDRs := []string{"127.0.0.1", "128.252.0.0/16"}

	addCertReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":         tc.exampleCA.CertPEM(),
			"policies":            "foo",
			"display_name":        name,
			"allowed_names":       "",
			"required_extensions": "",
			"lease":               1000,
			"bound_cidrs":         boundCIDRs,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	_, err = b.HandleRequest(t.Context(), addCertReq)
	if err != nil {
		t.Fatal(err)
	}

	readCertReq := &logical.Request{
		Operation:  logical.ReadOperation,
		Path:       "certs/" + name,
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	readResult, err := b.HandleRequest(t.Context(), readCertReq)
	if err != nil {
		t.Fatal(err)
	}
	cidrsResult := readResult.Data["bound_cidrs"].([]*sockaddr.SockAddrMarshaler)

	if cidrsResult[0].String() != boundCIDRs[0] ||
		cidrsResult[1].String() != boundCIDRs[1] {
		t.Fatalf("bound_cidrs couldn't be set correctly, EXPECTED: %v, ACTUAL: %v", boundCIDRs, cidrsResult)
	}

	loginReq := &logical.Request{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		Data: map[string]interface{}{
			"name": name,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	// override the remote address with an IPV4 that is authorized
	loginReq.Connection.RemoteAddr = "127.0.0.1/32"

	_, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestBackend_invalidCIDR(t *testing.T) {
	tc := setupTestCerts(t)
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}

	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	name := "web"

	addCertReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":         tc.exampleCA.CertPEM(),
			"policies":            "foo",
			"display_name":        name,
			"allowed_names":       "",
			"required_extensions": "",
			"lease":               1000,
			"bound_cidrs":         []string{"127.0.0.1/32", "128.252.0.0/16"},
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	_, err = b.HandleRequest(t.Context(), addCertReq)
	if err != nil {
		t.Fatal(err)
	}

	loginReq := &logical.Request{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		Data: map[string]interface{}{
			"name": name,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	// override the remote address with an IPV4 that isn't authorized
	loginReq.Connection.RemoteAddr = "127.0.0.1/8"

	_, err = b.HandleRequest(t.Context(), loginReq)
	if err == nil {
		t.Fatal("expected \"ERROR: permission denied\"")
	}
}

func testAccStepAddCRL(t *testing.T, crl []byte, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "crls/test",
		ConnState: &connState,
		Data: map[string]interface{}{
			"crl": crl,
		},
	}
}

func testAccStepReadCRL(t *testing.T, connState tls.ConnectionState, expectedSerial string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "crls/test",
		ConnState: &connState,
		Check: func(resp *logical.Response) error {
			crlInfo := CRLInfo{}
			err := mapstructure.Decode(resp.Data, &crlInfo)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(crlInfo.Serials) != 1 {
				t.Fatalf("bad: expected CRL with length 1, got %d", len(crlInfo.Serials))
			}
			if _, ok := crlInfo.Serials[expectedSerial]; !ok {
				t.Fatal("bad: expected serial number not found in CRL")
			}
			return nil
		},
	}
}

func testAccStepDeleteCRL(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "crls/test",
		ConnState: &connState,
	}
}

func testAccStepSetConfig(t *testing.T, conf config, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config",
		ConnState: &connState,
		Data: map[string]interface{}{
			"enable_identity_alias_metadata": conf.EnableIdentityAliasMetadata,
		},
	}
}

func testAccStepReadConfig(t *testing.T, conf config, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config",
		ConnState: &connState,
		Check: func(resp *logical.Response) error {
			value, ok := resp.Data["enable_identity_alias_metadata"]
			if !ok {
				t.Fatal("enable_identity_alias_metadata not found in response")
			}

			b, ok := value.(bool)
			if !ok {
				t.Fatal("bad: expected enable_identity_alias_metadata to be a bool")
			}

			if b != conf.EnableIdentityAliasMetadata {
				t.Fatalf("bad: expected enable_identity_alias_metadata to be %t, got %t", conf.EnableIdentityAliasMetadata, b)
			}

			return nil
		},
	}
}

func testAccStepLogin(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return testAccStepLoginWithName(t, connState, "")
}

func testAccStepLoginWithName(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth.TTL != 1000*time.Second {
				t.Fatalf("bad lease length: %#v", resp.Auth)
			}

			if certName != "" && resp.Auth.DisplayName != ("mnt-"+certName) {
				t.Fatalf("matched the wrong cert: %#v", resp.Auth.DisplayName)
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
		Data: map[string]interface{}{
			"name": certName,
		},
	}
}

func testAccStepLoginDefaultLease(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth.TTL != 1000*time.Second {
				t.Fatalf("bad lease length: %#v", resp.Auth)
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
	}
}

func testAccStepLoginWithMetadata(t *testing.T, connState tls.ConnectionState, certName string, metadata map[string]string, expectAliasMetadata bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			// Check for fixed metadata too
			metadata["cert_name"] = certName
			metadata["common_name"] = connState.PeerCertificates[0].Subject.CommonName
			metadata["serial_number"] = connState.PeerCertificates[0].SerialNumber.String()
			metadata["subject_key_id"] = certutil.GetHexFormatted(connState.PeerCertificates[0].SubjectKeyId, ":")
			metadata["authority_key_id"] = certutil.GetHexFormatted(connState.PeerCertificates[0].AuthorityKeyId, ":")

			for key, expected := range metadata {
				value, ok := resp.Auth.Metadata[key]
				if !ok {
					t.Fatalf("missing metadata key: %s", key)
				}

				if value != expected {
					t.Fatalf("expected metadata key %s to equal %s, but got: %s", key, expected, value)
				}

				if expectAliasMetadata {
					value, ok = resp.Auth.Alias.Metadata[key]
					if !ok {
						t.Fatalf("missing alias metadata key: %s", key)
					}

					if value != expected {
						t.Fatalf("expected metadata key %s to equal %s, but got: %s", key, expected, value)
					}
				} else {
					if len(resp.Auth.Alias.Metadata) > 0 {
						t.Fatal("found alias metadata keys, but should not have any")
					}
				}
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
		Data: map[string]interface{}{
			"metadata": metadata,
		},
	}
}

func testAccStepLoginInvalid(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return testAccStepLoginWithNameInvalid(t, connState, "")
}

func testAccStepLoginWithNameInvalid(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth != nil {
				return fmt.Errorf("should not be authorized: %#v", resp)
			}
			return nil
		},
		Data: map[string]interface{}{
			"name": certName,
		},
		ErrorOk: true,
	}
}

func testAccStepListCerts(
	t *testing.T, certs []string,
) []logicaltest.TestStep {
	return []logicaltest.TestStep{
		{
			Operation: logical.ListOperation,
			Path:      "certs",
			Check: func(resp *logical.Response) error {
				if resp == nil {
					return errors.New("nil response")
				}
				if resp.Data == nil {
					return errors.New("nil data")
				}
				if resp.Data["keys"] == interface{}(nil) {
					return errors.New("nil keys")
				}
				keys := resp.Data["keys"].([]string)
				if !reflect.DeepEqual(keys, certs) {
					return fmt.Errorf("mismatch: keys is %#v, certs is %#v", keys, certs)
				}
				return nil
			},
		}, {
			Operation: logical.ListOperation,
			Path:      "certs/",
			Check: func(resp *logical.Response) error {
				if resp == nil {
					return errors.New("nil response")
				}
				if resp.Data == nil {
					return errors.New("nil data")
				}
				if resp.Data["keys"] == interface{}(nil) {
					return errors.New("nil keys")
				}
				keys := resp.Data["keys"].([]string)
				if !reflect.DeepEqual(keys, certs) {
					return fmt.Errorf("mismatch: keys is %#v, certs is %#v", keys, certs)
				}

				return nil
			},
		},
	}
}

type allowed struct {
	names                string // allowed names in the certificate, looks at common, name, dns, email [depricated]
	common_names         string // allowed common names in the certificate
	dns                  string // allowed dns names in the SAN extension of the certificate
	emails               string // allowed email names in SAN extension of the certificate
	uris                 string // allowed uris in SAN extension of the certificate
	organizational_units string // allowed OUs in the certificate
	ext                  string // required extensions in the certificate
	metadata_ext         string // allowed metadata extensions to add to identity alias
}

func testAccStepCert(t *testing.T, name string, cert []byte, policies string, testData allowed, expectError bool) logicaltest.TestStep {
	return testAccStepCertWithExtraParams(t, name, cert, policies, testData, expectError, nil)
}

func testAccStepCertWithExtraParams(t *testing.T, name string, cert []byte, policies string, testData allowed, expectError bool, extraParams map[string]interface{}) logicaltest.TestStep {
	data := map[string]interface{}{
		"certificate":                  string(cert),
		"policies":                     policies,
		"display_name":                 name,
		"allowed_names":                testData.names,
		"allowed_common_names":         testData.common_names,
		"allowed_dns_sans":             testData.dns,
		"allowed_email_sans":           testData.emails,
		"allowed_uri_sans":             testData.uris,
		"allowed_organizational_units": testData.organizational_units,
		"required_extensions":          testData.ext,
		"allowed_metadata_extensions":  testData.metadata_ext,
		"lease":                        1000,
	}
	maps.Copy(data, extraParams)
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		ErrorOk:   expectError,
		Data:      data,
		Check: func(resp *logical.Response) error {
			if resp == nil && expectError {
				return errors.New("expected error but received nil")
			}
			return nil
		},
	}
}

func testAccStepReadCertPolicy(t *testing.T, name string, expectError bool, expected map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "certs/" + name,
		ErrorOk:   expectError,
		Data:      nil,
		Check: func(resp *logical.Response) error {
			if (resp == nil || len(resp.Data) == 0) && expectError {
				return errors.New("expected error but received nil")
			}
			for key, expectedValue := range expected {
				actualValue := resp.Data[key]
				if expectedValue != actualValue {
					return fmt.Errorf("Expected to get [%v]=[%v] but read [%v]=[%v] from server for certs/%v: %v", key, expectedValue, key, actualValue, name, resp)
				}
			}
			return nil
		},
	}
}

func testAccStepCertLease(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"lease":        1000,
		},
	}
}

func testAccStepCertTTL(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"ttl":          "1000s",
		},
	}
}

func testAccStepCertMaxTTL(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"ttl":          "1000s",
			"max_ttl":      "1200s",
		},
	}
}

func testAccStepCertNoLease(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
		},
	}
}

func testConnState(cert, ca *certyaml.Certificate) (tls.ConnectionState, error) {
	tlsCert, err := cert.TLSCertificate()
	if err != nil {
		return tls.ConnectionState{}, err
	}
	caCert, err := ca.X509Certificate()
	if err != nil {
		return tls.ConnectionState{}, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(&caCert)

	listenConf := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	dialConf := listenConf.Clone()
	// start a server
	list, err := tls.Listen("tcp", "127.0.0.1:0", listenConf)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer list.Close() //nolint:errcheck // try to close, ignore error

	// Accept connections.
	serverErrors := make(chan error, 1)
	connState := make(chan tls.ConnectionState)
	go func() {
		defer close(connState) //nolint:errcheck // try to close, ignore error
		serverConn, err := list.Accept()
		serverErrors <- err
		if err != nil {
			close(serverErrors)
			return
		}
		defer serverConn.Close()

		// Read the ping
		buf := make([]byte, 4)
		_, err = serverConn.Read(buf)
		if (err != nil) && (err != io.EOF) {
			serverErrors <- err
			close(serverErrors)
			return
		} else {
			// EOF is a reasonable error condition, so swallow it.
			serverErrors <- nil
		}
		close(serverErrors)
		connState <- serverConn.(*tls.Conn).ConnectionState()
	}()

	// Establish a connection from the client side and write a few bytes.
	clientErrors := make(chan error, 1)
	go func() {
		addr := list.Addr().String()
		conn, err := tls.Dial("tcp", addr, dialConf)
		clientErrors <- err
		if err != nil {
			close(clientErrors)
			return
		}
		defer conn.Close()

		// Write ping
		_, err = conn.Write([]byte("ping"))
		clientErrors <- err
		close(clientErrors)
	}()

	for err = range clientErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in client goroutine:%v", err)
		}
	}

	for err = range serverErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in server goroutine:%v", err)
		}
	}
	// Grab the current state
	return <-connState, nil
}

func Test_Renew(t *testing.T) {
	tc := setupTestCerts(t)
	storage := &logical.InmemStorage{}

	lb, err := Factory(t.Context(), &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 300 * time.Second,
			MaxLeaseTTLVal:     1800 * time.Second,
		},
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	b := lb.(*backend)
	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	req := &logical.Request{
		Connection: &logical.Connection{
			ConnState: &connState,
		},
		Storage: storage,
		Auth:    &logical.Auth{},
	}

	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        "test",
			"certificate": tc.exampleCA.CertPEM(),
			"policies":    "foo,bar",
		},
		Schema: pathCerts(b).Fields,
	}

	_, err = b.pathCertWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	empty_login_fd := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: pathLogin(b).Fields,
	}
	resp, err := b.pathLogin(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}
	req.Auth.InternalData = resp.Auth.InternalData
	req.Auth.Metadata = resp.Auth.Metadata
	req.Auth.LeaseOptions = resp.Auth.LeaseOptions
	req.Auth.Policies = resp.Auth.Policies
	req.Auth.TokenPolicies = req.Auth.Policies
	req.Auth.Period = resp.Auth.Period

	// Normal renewal
	resp, err = b.pathLoginRenew(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Change the policies -- this should fail
	fd.Raw["policies"] = "zip,zap"
	_, err = b.pathCertWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	_, err = b.pathLoginRenew(t.Context(), req, empty_login_fd)
	if err == nil {
		t.Fatal("expected error")
	}

	// Put the policies back, this should be okay
	fd.Raw["policies"] = "bar,foo"
	_, err = b.pathCertWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Add period value to cert entry
	period := 350 * time.Second
	fd.Raw["period"] = period.String()
	_, err = b.pathCertWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	if resp.Auth.Period != period {
		t.Fatalf("expected a period value of %s in the response, got: %s", period, resp.Auth.Period)
	}

	// Delete CA, make sure we can't renew
	_, err = b.pathCertDelete(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("got non-nil response from renew: %v", resp)
	}
}

func TestBackend_CertUpgrade(t *testing.T) {
	s := &logical.InmemStorage{}

	config := logical.TestBackendConfig()
	config.StorageView = s

	ctx := t.Context()

	b := Backend()
	if b == nil {
		t.Fatal("failed to create backend")
	}
	if err := b.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}

	foo := &CertEntry{
		Policies:   []string{"foo"},
		Period:     time.Second,
		TTL:        time.Second,
		MaxTTL:     time.Second,
		BoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
	}

	entry, err := logical.StorageEntryJSON("cert/foo", foo)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Put(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}

	certEntry, err := b.Cert(ctx, s, "foo")
	if err != nil {
		t.Fatal(err)
	}

	exp := &CertEntry{
		Policies:   []string{"foo"},
		Period:     time.Second,
		TTL:        time.Second,
		MaxTTL:     time.Second,
		BoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
		TokenParams: tokenutil.TokenParams{
			TokenPolicies:   []string{"foo"},
			TokenPeriod:     time.Second,
			TokenTTL:        time.Second,
			TokenMaxTTL:     time.Second,
			TokenBoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
		},
	}
	if diff := deep.Equal(certEntry, exp); diff != nil {
		t.Fatal(diff)
	}
}

func TestBackend_RegressionDifferentTrustedLeaf(t *testing.T) {
	leafA := &certyaml.Certificate{Subject: "cn=a.openbao.org"}
	leafB := &certyaml.Certificate{Subject: "cn=b.openbao.org"}

	// Cert auth method
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the first leaf cert as a trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/trusted-leaf", map[string]interface{}{
		"display_name": "trusted-cert",
		"policies":     "default",
		"certificate":  string(leafA.CertPEM()),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Parse the leaf and create a cloned copy of it with a different subject
	// name to validate against HCSEC-2025-18 (CVE-2025-6037).
	tamperedLeafA, _ := leafA.X509Certificate()
	tamperedLeafA.Subject.CommonName = "a-fake.openbao.org"
	tamperedLeafA.Raw = nil
	tamperedLeafA.RawIssuer = nil
	tamperedLeafA.RawSubject = nil
	tamperedLeafA.RawSubjectPublicKeyInfo = nil
	tamperedLeafA.RawTBSCertificate = nil
	leafAKey, _ := leafA.PrivateKey()
	certATampered, err := x509.CreateCertificate(rand.Reader, &tamperedLeafA, &tamperedLeafA, tamperedLeafA.PublicKey, leafAKey)
	require.NoError(t, err)
	regTamperedLeafCertA := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certATampered,
	})

	// Also create a variant of key B with the same subject as key A to detect
	// attempted reuse that way.
	tamperedLeafB, _ := leafB.X509Certificate()
	tamperedLeafB.Subject.CommonName = "a.openbao.org"
	tamperedLeafB.Raw = nil
	tamperedLeafB.RawIssuer = nil
	tamperedLeafB.RawSubject = nil
	tamperedLeafB.RawSubjectPublicKeyInfo = nil
	tamperedLeafB.RawTBSCertificate = nil
	leafBKey, _ := leafB.PrivateKey()
	certBTampered, err := x509.CreateCertificate(rand.Reader, &tamperedLeafB, &tamperedLeafB, tamperedLeafB.PublicKey, leafBKey)
	require.NoError(t, err)
	regTamperedLeafCertB := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBTampered,
	})

	// Create temporary files for CA cert, client cert and client cert key.
	// This is used to configure TLS in the api client.
	tempDir := t.TempDir()
	caCertFile := filepath.Join(tempDir, "ca.pem")
	leafACertFile := filepath.Join(tempDir, "leafA.pem")
	leafAKeyFile := filepath.Join(tempDir, "leafA-key.pem")
	leafBCertFile := filepath.Join(tempDir, "leafB.pem")
	leafBKeyFile := filepath.Join(tempDir, "leafB-key.pem")
	tamperedACertFile := filepath.Join(tempDir, "tamperedA.pem")
	tamperedBCertFile := filepath.Join(tempDir, "tamperedB.pem")

	require.NoError(t, os.WriteFile(caCertFile, []byte(cluster.CACertPEM), 0o600))
	require.NoError(t, leafA.WritePEM(leafACertFile, leafAKeyFile))
	require.NoError(t, leafB.WritePEM(leafBCertFile, leafBKeyFile))
	require.NoError(t, os.WriteFile(tamperedACertFile, regTamperedLeafCertA, 0o600))
	require.NoError(t, os.WriteFile(tamperedBCertFile, regTamperedLeafCertB, 0o600))

	// This function is a copy-pasta from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with the leaf
	// certificate generated above.
	getAPIClient := func(port int, tlsConfig *tls.Config, leafCert string, leafKey string) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return errors.New("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the above issued certificates as the client certificates
		err := config.ConfigureTLS(&api.TLSConfig{
			CACert:     caCertFile,
			ClientCert: leafCert,
			ClientKey:  leafKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the incorrect leaf; it should fail.
	newBClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), leafBCertFile, leafBKeyFile)

	secret, err := newBClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err == nil {
		t.Fatalf("when logging in with different leaf from trusted, expected err but got none: err=%v / secret=%v", err, secret)
	}
	if secret != nil {
		t.Fatalf("when logging in with different leaf from trusted, expected empty secret but got %v", secret)
	}

	// Create a new API client with the correct leaf; it should succeed.
	newAClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), leafACertFile, leafAKeyFile)

	secret, err = newAClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatal("expected a successful authentication")
	}

	// Putting an incorrect leaf into the Processed headers should be ignored.
	//
	// This would fail if we actually used our tampered certificate.
	newAClient.AddHeader(vaulthttp.ProcessedForwardedClientCertHeader, url.QueryEscape(base64.StdEncoding.EncodeToString(certBTampered)))
	newAClient.AddHeader("X-Processed-Tls-Client-Certificate-Resp", url.QueryEscape(base64.StdEncoding.EncodeToString(certBTampered)))

	secret, err = newAClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotNil(t, secret.Auth)
	require.NotEmpty(t, secret.Auth.ClientToken)

	// Create a new API client with the tampered leaves; it should fail.
	tamperedAClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), tamperedACertFile, leafAKeyFile)

	secret, err = tamperedAClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err == nil {
		t.Fatalf("when logging in with different leaf from trusted, expected err but got none: err=%v / secret=%v", err, secret)
	}
	if secret != nil {
		t.Fatalf("when logging in with different leaf from trusted, expected empty secret but got %v", secret)
	}

	tamperedBClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), tamperedBCertFile, leafBKeyFile)

	secret, err = tamperedBClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err == nil {
		t.Fatalf("when logging in with different leaf from trusted, expected err but got none: err=%v / secret=%v", err, secret)
	}
	if secret != nil {
		t.Fatalf("when logging in with different leaf from trusted, expected empty secret but got %v", secret)
	}
}

func TestBackend_IntegrationForwardedCerts(t *testing.T) {
	tc := setupTestCerts(t)
	core, _, root := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
	})
	vault.TestWaitActive(t, core)

	ln, addr := vaulthttp.TestServerWithCertForwarding(t, core)
	defer ln.Close() //nolint:errcheck // try to close, ignore error

	config := api.DefaultConfig()
	config.Address = addr

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(root)

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	require.NoError(t, err)

	// Set the first leaf cert as a trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/leaf", map[string]interface{}{
		"display_name": "trusted-cert",
		"policies":     "default",
		"certificate":  string(tc.exampleCert.CertPEM()),
	})
	require.NoError(t, err)

	// Create an unauthenticated client.
	unauthedClient, err := client.Clone()
	require.NoError(t, err)
	unauthedClient.SetToken("")

	// Add auth header
	unauthedClient.AddHeader("Client-Cert", url.QueryEscape(base64.StdEncoding.EncodeToString(tc.exampleCert.GeneratedCert.Certificate[0])))

	// Authentication should succeed with the forwarded header.
	resp, err := unauthedClient.Logical().Write("auth/cert/login", map[string]interface{}{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	require.NotEmpty(t, resp.Auth.ClientToken)
}
