// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Ensure our special envvars are not present
	os.Setenv("BAO_ADDR", "")
	os.Setenv("BAO_TOKEN", "")
}

func TestNewConfig_envvar(t *testing.T) {
	t.Setenv("BAO_ADDR", "https://vault.mycompany.com")

	config := NewConfig()
	require.Empty(t, config.Address)

	t.Setenv("BAO_TOKEN", "testing")

	client, err := NewClient(config)
	require.NoError(t, err)

	token := client.Token()
	require.Empty(t, token)
}

func TestDefaultConfig_envvar(t *testing.T) {
	t.Setenv("BAO_ADDR", "https://vault.mycompany.com")

	config := DefaultConfig()
	require.Equal(t, "https://vault.mycompany.com", config.Address)

	t.Setenv("BAO_TOKEN", "testing")

	client, err := NewClient(config)
	require.NoError(t, err)

	token := client.Token()
	require.Equal(t, "testing", token)
}

func TestClientDefaultHttpClient(t *testing.T) {
	_, err := NewClient(&Config{
		HttpClient: http.DefaultClient,
	})
	require.NoError(t, err)
}

func TestClientNilConfig(t *testing.T) {
	client, err := NewClient(nil)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestClientDefaultHttpClient_unixSocket(t *testing.T) {
	t.Setenv("BAO_AGENT_ADDR", "unix:///var/run/vault.sock")

	client, err := NewClient(nil)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, "http", client.addr.Scheme)
	require.Equal(t, "localhost", client.addr.Host)
}

func TestClientSetAddress(t *testing.T) {
	client, err := NewClient(nil)
	require.NoError(t, err)

	// Start with TCP address using HTTP
	err = client.SetAddress("http://172.168.2.1:8300")
	require.NoError(t, err)
	require.Equalf(t, "172.168.2.1:8300", client.addr.Host, "bad: expected: '172.168.2.1:8300' actual: %q", client.addr.Host)

	// Test switching to Unix Socket address from TCP address
	err = client.SetAddress("unix:///var/run/vault.sock")
	require.NoError(t, err)
	require.Equalf(t, "http", client.addr.Scheme, "bad: expected: 'http' actual: %q", client.addr.Scheme)
	require.Equalf(t, "localhost", client.addr.Host, "bad: expected: 'localhost' actual: %q", client.addr.Host)
	require.Emptyf(t, client.addr.Path, "bad: expected '' actual: %q", client.addr.Path)
	require.NotNil(t, client.config.HttpClient.Transport.(*http.Transport).DialContext, "bad: expected DialContext to not be nil")

	// Test switching to TCP address from Unix Socket address
	err = client.SetAddress("http://172.168.2.1:8300")
	require.NoError(t, err)
	require.Equalf(t, "172.168.2.1:8300", client.addr.Host, "bad: expected: '172.168.2.1:8300' actual: %q", client.addr.Host)
	require.Equalf(t, "http", client.addr.Scheme, "bad: expected: 'http' actual: %q", client.addr.Scheme)
}

func TestClientToken(t *testing.T) {
	tokenValue := "foo"
	handler := func(w http.ResponseWriter, req *http.Request) {}

	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	client, err := NewClient(config)
	require.NoError(t, err)

	client.SetToken(tokenValue)

	// Verify the token is set
	v := client.Token()
	require.Equalf(t, tokenValue, v, "bad: %s", v)

	client.ClearToken()

	// Verify the client token cleared
	v = client.Token()
	require.Empty(t, v)
}

func TestClientHostHeader(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.Host))
	}
	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	config.Address = strings.ReplaceAll(config.Address, "127.0.0.1", "localhost")
	client, err := NewClient(config)
	require.NoError(t, err)

	// Set the token manually
	client.SetToken("foo")

	resp, err := client.RawRequest(client.NewRequest(http.MethodPut, "/"))
	require.NoError(t, err)

	// Copy the response
	var buf bytes.Buffer
	io.Copy(&buf, resp.Body)

	// Verify we got the response from the primary
	modifiedAddress := strings.ReplaceAll(config.Address, "http://", "")
	require.Equalf(t, modifiedAddress, buf.String(), "Bad address: %s", buf.String())
}

func TestClientBadToken(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {}

	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	client, err := NewClient(config)
	require.NoError(t, err)

	client.SetToken("foo")

	_, err = client.RawRequest(client.NewRequest(http.MethodPut, "/"))
	require.NoError(t, err)

	client.SetToken("foo\u007f")
	_, err = client.RawRequest(client.NewRequest(http.MethodPut, "/"))

	require.ErrorContains(t, err, "printable", "expected error due to bad token")
}

func TestClientDisableRedirects(t *testing.T) {
	tests := map[string]struct {
		statusCode       int
		expectedNumReqs  int
		disableRedirects bool
	}{
		"Disabled redirects: Moved permanently":  {statusCode: 301, expectedNumReqs: 1, disableRedirects: true},
		"Disabled redirects: Found":              {statusCode: 302, expectedNumReqs: 1, disableRedirects: true},
		"Disabled redirects: Temporary Redirect": {statusCode: 307, expectedNumReqs: 1, disableRedirects: true},
		"Enable redirects: Moved permanently":    {statusCode: 301, expectedNumReqs: 2, disableRedirects: false},
	}

	for name, tc := range tests {
		test := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			numReqs := 0
			var config *Config

			respFunc := func(w http.ResponseWriter, req *http.Request) {
				// Track how many requests the server has handled
				numReqs++
				// Send back the relevant status code and generate a location
				w.Header().Set("Location", fmt.Sprintf(config.Address+"/reqs/%v", numReqs))
				w.WriteHeader(test.statusCode)
			}

			config, ln := testHTTPServer(t, http.HandlerFunc(respFunc))
			config.DisableRedirects = test.disableRedirects
			defer ln.Close()

			client, err := NewClient(config)
			require.NoErrorf(t, err, "%s: error %v", name, err)

			req := client.NewRequest("GET", "/")
			resp, err := client.rawRequestWithContext(t.Context(), req)
			require.NoErrorf(t, err, "%s: error %v", name, err)

			require.Equalf(t, test.expectedNumReqs, numReqs, "%s: expected %v request(s) but got %v", name, test.expectedNumReqs, numReqs)

			require.Equalf(t, test.statusCode, resp.StatusCode, "%s: expected status code %v got %v", name, test.statusCode, resp.StatusCode)

			location, err := resp.Location()
			require.NoErrorf(t, err, "%s error %v", name, err)

			require.NotEqualf(t, req.URL.String(), location.String(), "%s: expected request URL %v to be different from redirect URL %v", name, req.URL, resp.Request.URL)
		})
	}
}

func TestClientRedirect(t *testing.T) {
	primary := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}
	config, ln := testHTTPServer(t, http.HandlerFunc(primary))
	defer ln.Close()

	standby := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Location", config.Address)
		w.WriteHeader(307)
	}
	config2, ln2 := testHTTPServer(t, http.HandlerFunc(standby))
	defer ln2.Close()

	client, err := NewClient(config2)
	require.NoError(t, err)

	// Set the token manually
	client.SetToken("foo")

	// Do a raw "/" request
	resp, err := client.RawRequest(client.NewRequest(http.MethodPut, "/"))
	require.NoError(t, err)

	// Copy the response
	var buf bytes.Buffer
	io.Copy(&buf, resp.Body)

	// Verify we got the response from the primary
	require.Equalf(t, "test", buf.String(), "Bad: %s", buf.String())
}

func TestDefaulRetryPolicy(t *testing.T) {
	cases := map[string]struct {
		resp      *http.Response
		err       error
		expect    bool
		expectErr error
	}{
		"retry on error": {
			err:    errors.New("error"),
			expect: true,
		},
		"don't retry on 200": {
			resp: &http.Response{
				StatusCode: http.StatusOK,
			},
		},
		"don't retry on 4xx": {
			resp: &http.Response{
				StatusCode: http.StatusBadRequest,
			},
		},
		"don't retry on 501": {
			resp: &http.Response{
				StatusCode: http.StatusNotImplemented,
			},
		},
		"retry on 500": {
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
			},
			expect: true,
		},
		"retry on 5xx": {
			resp: &http.Response{
				StatusCode: http.StatusGatewayTimeout,
			},
			expect: true,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			retry, err := DefaultRetryPolicy(t.Context(), test.resp, test.err)
			require.Equalf(t, test.expect, retry, "expected to retry request: '%t', but actual result was: '%t'", test.expect, retry)
			require.Equalf(t, test.expectErr, err, "expected error from retry policy: %q, but actual result was: %q", err, test.expectErr)
		})
	}
}

func TestClientEnvSettings(t *testing.T) {
	cwd, _ := os.Getwd()

	caCertBytes, err := os.ReadFile(cwd + "/test-fixtures/keys/cert.pem")
	require.NoError(t, err)

	t.Setenv(EnvVaultCACert, cwd+"/test-fixtures/keys/cert.pem")
	t.Setenv(EnvVaultCACertBytes, string(caCertBytes))
	t.Setenv(EnvVaultCAPath, cwd+"/test-fixtures/keys")
	t.Setenv(EnvVaultClientCert, cwd+"/test-fixtures/keys/cert.pem")
	t.Setenv(EnvVaultClientKey, cwd+"/test-fixtures/keys/key.pem")
	t.Setenv(EnvVaultSkipVerify, "true")
	t.Setenv(EnvVaultMaxRetries, "5")
	t.Setenv(EnvVaultDisableRedirects, "true")

	config := DefaultConfig()

	err = config.ReadEnvironment()
	require.NoErrorf(t, err, "error reading environment: %v", err)

	tlsConfig := config.HttpClient.Transport.(*http.Transport).TLSClientConfig
	require.False(t, x509.NewCertPool().Equal(tlsConfig.RootCAs), "expected a cert pool with at least one subject")
	require.NotNil(t, tlsConfig.GetClientCertificate, "bad: expected client tls config to have a certificate getter")
	require.Truef(t, tlsConfig.InsecureSkipVerify, "bad: %v", tlsConfig.InsecureSkipVerify)
	require.Truef(t, config.DisableRedirects, "bad: expected disable redirects to be true: %v", config.DisableRedirects)
}

func TestClientDeprecatedEnvSettings(t *testing.T) {
	t.Setenv(EnvVaultInsecure, "true")

	config := DefaultConfig()
	err := config.ReadEnvironment()
	require.NoErrorf(t, err, "error reading environment: %v", err)

	tlsConfig := config.HttpClient.Transport.(*http.Transport).TLSClientConfig
	require.Truef(t, tlsConfig.InsecureSkipVerify, "bad: %v", tlsConfig.InsecureSkipVerify)
}

func TestConfigureTLS(t *testing.T) {
	cwd, _ := os.Getwd()
	caCertPath := cwd + "/test-fixtures/keys/cert.pem"
	caPathDir := filepath.Dir(caCertPath)
	clientCertPath := cwd + "/test-fixtures/keys/cert.pem"
	badClientCertPath := cwd + "/test-fixtures/keys/bad-cert.pem"
	clientKeyPath := cwd + "/test-fixtures/keys/key.pem"
	badClientKeyPath := cwd + "/test-fixtures/keys/bad-key.pem"

	caCertBytes, err := os.ReadFile(caCertPath)
	require.NoError(t, err)

	clientCertBytes, err := os.ReadFile(clientCertPath)
	require.NoError(t, err)

	badClientCertBytes, err := os.ReadFile(badClientCertPath)
	require.NoError(t, err)

	clientKeyBytes, err := os.ReadFile(clientKeyPath)
	require.NoError(t, err)

	badClientKeyBytes, err := os.ReadFile(badClientKeyPath)
	require.NoError(t, err)

	tests := []struct {
		name      string
		tlsConfig *TLSConfig
		assert    func(t *testing.T, c *Config)

		wantErr bool
	}{
		{
			name:      "valid cert and key file paths",
			tlsConfig: &TLSConfig{ClientCert: clientCertPath, ClientKey: clientKeyPath},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.GetClientCertificate)

				cert, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				assert.NotEmpty(t, cert.Certificate)

				assert.Equal(t, clientCertPath, c.curlClientCert)
				assert.Equal(t, clientKeyPath, c.curlClientKey)
			},
		},
		{
			name:      "invalid cert file path",
			tlsConfig: &TLSConfig{ClientCert: "/nonexistent/cert.pem", ClientKey: clientKeyPath},
			wantErr:   true,
		},
		{
			name:      "invalid key file path",
			tlsConfig: &TLSConfig{ClientCert: clientCertPath, ClientKey: "/nonexistent/key.pem"},
			wantErr:   true,
		},
		{
			name:      "corrupt cert and key files",
			tlsConfig: &TLSConfig{ClientCert: badClientCertPath, ClientKey: badClientKeyPath},
			wantErr:   true,
		},
		{
			name:      "invalid PEM cert bytes",
			tlsConfig: &TLSConfig{ClientCertBytes: badClientCertBytes, ClientKeyBytes: clientKeyBytes},
			wantErr:   true,
		},
		{
			name:      "invalid PEM key bytes",
			tlsConfig: &TLSConfig{ClientCertBytes: clientCertBytes, ClientKeyBytes: badClientKeyBytes},
			wantErr:   true,
		},
		{
			name:      "invalid PEM cert and key bytes",
			tlsConfig: &TLSConfig{ClientCertBytes: badClientCertBytes, ClientKeyBytes: badClientKeyBytes},
			wantErr:   true,
		},
		{
			name:      "valid PEM bundle bytes",
			tlsConfig: &TLSConfig{ClientCertBytes: clientCertBytes, ClientKeyBytes: clientKeyBytes},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.GetClientCertificate)

				cert, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				assert.NotEmpty(t, cert.Certificate)

				assert.Equal(t, "passed-in-memory", c.curlClientCert)
				assert.Equal(t, "passed-in-memory", c.curlClientKey)
			},
		},
		{
			// actually fine
			name:      "empty config",
			tlsConfig: &TLSConfig{},
		},
		{
			name:      "only ClientCert without ClientKey",
			tlsConfig: &TLSConfig{ClientCert: clientCertPath},
			wantErr:   true,
		},
		{
			name:      "only ClientKey without ClientCert",
			tlsConfig: &TLSConfig{ClientKey: clientKeyPath},
			wantErr:   true,
		},
		{
			name:      "CACert from file path",
			tlsConfig: &TLSConfig{CACert: caCertPath, ClientCert: clientCertPath, ClientKey: clientKeyPath},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.RootCAs, "RootCAs should be set")
				assert.Equal(t, caCertPath, c.curlCACert)
			},
		},
		{
			name:      "CACert invalid file path",
			tlsConfig: &TLSConfig{CACert: "/nonexistent/ca.pem"},
			wantErr:   true,
		},
		{
			name:      "CACertBytes set",
			tlsConfig: &TLSConfig{CACertBytes: caCertBytes, ClientCert: clientCertPath, ClientKey: clientKeyPath},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.RootCAs, "RootCAs should be set from bytes")
				assert.Equal(t, "passed-in-memory", c.curlCACert)
			},
		},
		{
			name:      "CAPath directory",
			tlsConfig: &TLSConfig{CAPath: caPathDir, ClientCert: clientCertPath, ClientKey: clientKeyPath},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.RootCAs, "RootCAs should be set from CAPath")
			},
		},
		{
			name:      "CAPath invalid directory",
			tlsConfig: &TLSConfig{CAPath: "/nonexistent/cadir/"},
			wantErr:   true,
		},
		{
			name:      "GetClientCertificate callback correctness - file paths",
			tlsConfig: &TLSConfig{ClientCert: clientCertPath, ClientKey: clientKeyPath},
			assert: func(t *testing.T, c *Config) {
				expected, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
				require.NoError(t, err)

				tr := c.HttpClient.Transport.(*http.Transport)
				got, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				require.Len(t, got.Certificate, len(expected.Certificate))
				assert.Equal(t, expected.Certificate[0], got.Certificate[0],
					"DER bytes of the leaf certificate should match")
			},
		},
		{
			name:      "GetClientCertificate callback correctness - PEM bundle bytes",
			tlsConfig: &TLSConfig{ClientCertBytes: clientCertBytes, ClientKeyBytes: clientKeyBytes},
			assert: func(t *testing.T, c *Config) {
				expected, err := tls.X509KeyPair(caCertBytes, clientKeyBytes)
				require.NoError(t, err)

				tr := c.HttpClient.Transport.(*http.Transport)
				got, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				require.Len(t, got.Certificate, len(expected.Certificate))
				assert.Equal(t, expected.Certificate[0], got.Certificate[0],
					"DER bytes of the leaf certificate should match")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			err := c.configureTLS(tc.tlsConfig)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.assert != nil {
				tc.assert(t, c)
			}
		})
	}
}

func TestClientConfigureTLS(t *testing.T) {
	cwd, _ := os.Getwd()
	caCertPath := cwd + "/test-fixtures/keys/cert.pem"

	tests := []struct {
		name      string
		tlsConfig *TLSConfig
		wantErr   assert.ErrorAssertionFunc
		assert    func(t *testing.T, c *Config)
	}{
		{
			name:      "updates RootCAs on existing client",
			tlsConfig: &TLSConfig{CACert: caCertPath},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				require.NotNil(t, tr.TLSClientConfig.RootCAs,
					"RootCAs should be set after ConfigureTLS")
			},
		},
		{
			name:      "invalid CA cert returns error",
			tlsConfig: &TLSConfig{CACert: "/nonexistent/ca.pem"},
			wantErr: func(t assert.TestingT, err error, _ ...any) bool {
				return assert.ErrorContains(t, err, "Error loading CA File")
			},
		},
		{
			name:      "updates InsecureSkipVerify",
			tlsConfig: &TLSConfig{Insecure: true},
			assert: func(t *testing.T, c *Config) {
				tr := c.HttpClient.Transport.(*http.Transport)
				assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultConfig()
			client, err := NewClient(config)
			require.NoError(t, err)

			err = client.ConfigureTLS(tc.tlsConfig)
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}

			require.NoError(t, err)
			if tc.assert != nil {
				tc.assert(t, config)
			}
		})
	}
}

// TestClientConfigureTLS_Reload verifies that calling ConfigureTLS a second
// time re-reads certificates from disk and updates the transport's RootCAs,
// simulating a CA rotation.
func TestClientConfigureTLS_Reload(t *testing.T) {
	cwd, _ := os.Getwd()
	caCertPath := cwd + "/test-fixtures/keys/cert.pem"

	config := DefaultConfig()
	err := config.ConfigureTLS(&TLSConfig{CACert: caCertPath})
	require.NoError(t, err)

	client, err := NewClient(config)
	require.NoError(t, err)

	tr := config.HttpClient.Transport.(*http.Transport)
	firstRootCAs := tr.TLSClientConfig.RootCAs
	require.NotNil(t, firstRootCAs)

	// Second call re-reads the same file from disk, proving the pool is replaced.
	err = client.ConfigureTLS(&TLSConfig{CACert: caCertPath})
	require.NoError(t, err)

	secondRootCAs := tr.TLSClientConfig.RootCAs
	require.NotNil(t, secondRootCAs)
	assert.True(t, secondRootCAs.Equal(firstRootCAs),
		"pools loaded from the same file should be equal")
}

func TestClientEnvNamespace(t *testing.T) {
	var seenNamespace string
	handler := func(w http.ResponseWriter, req *http.Request) {
		seenNamespace = req.Header.Get(NamespaceHeaderName)
	}
	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	t.Setenv(EnvVaultNamespace, "test")

	client, err := NewClient(config)
	require.NoError(t, err)

	_, err = client.RawRequest(client.NewRequest(http.MethodGet, "/"))
	require.NoError(t, err)

	require.Equal(t, "test", seenNamespace)
}

func TestParsingRateAndBurst(t *testing.T) {
	var (
		correctFormat                    = "400:400"
		observedRate, observedBurst, err = parseRateLimit(correctFormat)
		expectedRate, expectedBurst      = float64(400), 400
	)
	assert.NoError(t, err)
	assert.Equalf(t, expectedRate, observedRate, "Expected rate %v but found %v", expectedRate, observedRate)
	assert.Equalf(t, expectedBurst, observedBurst, "Expected burst %v but found %v", expectedBurst, observedBurst)
}

func TestParsingRateOnly(t *testing.T) {
	var (
		correctFormat                    = "400"
		observedRate, observedBurst, err = parseRateLimit(correctFormat)
		expectedRate, expectedBurst      = float64(400), 400
	)
	assert.NoError(t, err)
	assert.Equalf(t, expectedRate, observedRate, "Expected rate %v but found %v", expectedRate, observedRate)
	assert.Equalf(t, expectedBurst, observedBurst, "Expected burst %v but found %v", expectedBurst, observedBurst)
}

func TestParsingErrorCase(t *testing.T) {
	incorrectFormat := "foobar"
	_, _, err := parseRateLimit(incorrectFormat)
	require.Errorf(t, err, "Expected error, found no error")
}

func TestClientTimeoutSetting(t *testing.T) {
	t.Setenv(EnvVaultClientTimeout, "10")
	config := DefaultConfig()
	config.ReadEnvironment()
	_, err := NewClient(config)
	require.NoError(t, err)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rt roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

func TestClientNonTransportRoundTripper(t *testing.T) {
	client := &http.Client{
		Transport: roundTripperFunc(http.DefaultTransport.RoundTrip),
	}

	_, err := NewClient(&Config{
		HttpClient: client,
	})
	require.NoError(t, err)
}

func TestClientNonTransportRoundTripperUnixAddress(t *testing.T) {
	client := &http.Client{
		Transport: roundTripperFunc(http.DefaultTransport.RoundTrip),
	}

	_, err := NewClient(&Config{
		HttpClient: client,
		Address:    "unix:///var/run/vault.sock",
	})
	require.Error(t, err, "bad: expected error got nil")
}

func TestClone(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		headers *http.Header
		token   string
	}{
		{
			name:   "default",
			config: DefaultConfig(),
		},
		{
			name: "cloneHeaders",
			config: &Config{
				CloneHeaders: true,
			},
			headers: &http.Header{
				"X-foo": []string{"bar"},
				"X-baz": []string{"qux"},
			},
		},
		{
			name: "cloneToken",
			config: &Config{
				CloneToken: true,
			},
			token: "cloneToken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, err := NewClient(tt.config)
			require.NoErrorf(t, err, "NewClient failed: %v", err)

			// Set all of the things that we provide setter methods for, which modify config values
			err = parent.SetAddress("http://example.com:8080")
			require.NoErrorf(t, err, "SetAddress failed: %v", err)

			clientTimeout := time.Until(time.Now().AddDate(0, 0, 1))
			parent.SetClientTimeout(clientTimeout)

			checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				return true, nil
			}
			parent.SetCheckRetry(checkRetry)

			parent.SetLogger(hclog.NewNullLogger())

			parent.SetLimiter(5.0, 10)
			parent.SetMaxRetries(5)
			parent.SetOutputCurlString(true)
			parent.SetOutputPolicy(true)
			parent.SetSRVLookup(true)

			if tt.headers != nil {
				parent.SetHeaders(*tt.headers)
			}

			if tt.token != "" {
				parent.SetToken(tt.token)
			}

			clone, err := parent.Clone()
			require.NoErrorf(t, err, "Clone failed: %v", err)

			require.Equalf(t, parent.Address(), clone.Address(), "addresses don't match: %v vs %v", parent.Address(), clone.Address())
			require.Equalf(t, parent.ClientTimeout(), clone.ClientTimeout(), "timeouts don't match: %v vs %v", parent.ClientTimeout(), clone.ClientTimeout())

			// Checking CheckRetry parent and clone not equal
			checkRetryEquality := (parent.CheckRetry() != nil && clone.CheckRetry() == nil) || (parent.CheckRetry() == nil && clone.CheckRetry() != nil)
			require.Falsef(t, checkRetryEquality, "checkRetry functions don't match.")

			// Checking Limiter parent and clone not equal
			limiterEquality := (parent.Limiter() != nil && clone.Limiter() == nil) || (parent.Limiter() == nil && clone.Limiter() != nil)
			require.Falsef(t, limiterEquality, "limiters don't match: %v vs %v", parent.Limiter(), clone.Limiter())

			require.Equalf(t, parent.Limiter().Limit(), clone.Limiter().Limit(), "limiter limits don't match: %v vs %v", parent.Limiter().Limit(), clone.Limiter().Limit())
			require.Equalf(t, parent.Limiter().Burst(), clone.Limiter().Burst(), "limiter bursts don't match: %v vs %v", parent.Limiter().Burst(), clone.Limiter().Burst())

			require.Equalf(t, parent.MaxRetries(), clone.MaxRetries(), "maxRetries don't match: %v vs %v", parent.MaxRetries(), clone.MaxRetries())
			require.NotEqualf(t, parent.OutputCurlString(), clone.OutputCurlString(), "outputCurlString was copied over when it shouldn't have been: %v and %v", parent.OutputCurlString(), clone.OutputCurlString())
			require.Equalf(t, parent.SRVLookup(), clone.SRVLookup(), "SRVLookup doesn't match: %v vs %v", parent.SRVLookup(), clone.SRVLookup())

			if tt.config.CloneHeaders {
				require.Equalf(t, parent.Headers(), clone.Headers(), "Headers() don't match: %v vs %v", parent.Headers(), clone.Headers())
				require.Equalf(t, parent.config.CloneHeaders, clone.config.CloneHeaders, "config.CloneHeaders doesn't match: %v vs %v", parent.config.CloneHeaders, clone.config.CloneHeaders)
				if tt.headers != nil {
					require.Equalf(t, *tt.headers, clone.Headers(), "expected headers %v, actual %v", *tt.headers, clone.Headers())
				}
			}
			if tt.config.CloneToken {
				require.NotEmpty(t, tt.token, "test requires a non-empty token")
				require.Equalf(t, parent.config.CloneToken, clone.config.CloneToken, "config.CloneToken doesn't match: %v vs %v", parent.config.CloneToken, clone.config.CloneToken)
				require.Equalf(t, parent.token, clone.token, "tokens do not match: %v vs %v", parent.token, clone.token)
			} else {
				// assumes `BAO_TOKEN` is unset or has an empty value.
				require.Empty(t, clone.token)
			}
		})
	}
}

func TestSetHeadersRaceSafe(t *testing.T) {
	client, err1 := NewClient(nil)
	if err1 != nil {
		t.Fatalf("NewClient failed: %v", err1)
	}

	start := make(chan any)
	done := make(chan any)

	testPairs := map[string]string{
		"soda":    "rootbeer",
		"veggie":  "carrots",
		"fruit":   "apples",
		"color":   "red",
		"protein": "egg",
	}

	for key, value := range testPairs {
		tmpKey := key
		tmpValue := value
		go func() {
			<-start
			// This test fails if here, you replace client.AddHeader(tmpKey, tmpValue) with:
			// 	headerCopy := client.Header()
			// 	headerCopy.AddHeader(tmpKey, tmpValue)
			// 	client.SetHeader(headerCopy)
			client.AddHeader(tmpKey, tmpValue)
			done <- true
		}()
	}

	// Start everyone at once.
	close(start)

	// Wait until everyone is done.
	for i := 0; i < len(testPairs); i++ {
		<-done
	}

	// Check that all the test pairs are in the resulting
	// headers.
	resultingHeaders := client.Headers()
	for key, value := range testPairs {
		require.Equal(t, value, resultingHeaders.Get(key), "expected "+value+" for "+key)
	}
}

func TestClient_SetCloneToken(t *testing.T) {
	tests := []struct {
		name  string
		calls []bool
	}{
		{
			name:  "false",
			calls: []bool{false},
		},
		{
			name:  "true",
			calls: []bool{true},
		},
		{
			name:  "multi",
			calls: []bool{true, false, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				config: &Config{},
			}

			var expected bool
			for _, v := range tt.calls {
				actual := c.CloneToken()
				require.Equalf(t, expected, actual, "expected %v, actual %v", expected, actual)

				expected = v
				c.SetCloneToken(expected)
				actual = c.CloneToken()
				require.Equalf(t, expected, actual, "SetCloneToken(): expected %v, actual %v", expected, actual)
			}
		})
	}
}

func TestClientWithNamespace(t *testing.T) {
	var ns string
	handler := func(w http.ResponseWriter, req *http.Request) {
		ns = req.Header.Get(NamespaceHeaderName)
	}
	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	// set up a client with a namespace
	client, err := NewClient(config)
	require.NoErrorf(t, err, "err: %s", err)

	ogNS := "test"
	client.SetNamespace(ogNS)
	_, err = client.rawRequestWithContext(
		t.Context(),
		client.NewRequest(http.MethodGet, "/"),
	)
	require.NoErrorf(t, err, "err: %s", err)
	require.Equalf(t, ogNS, ns, "Expected namespace: %q, got %q", ogNS, ns)

	// make a call with a temporary namespace
	newNS := "new-namespace"
	_, err = client.WithNamespace(newNS).rawRequestWithContext(
		t.Context(),
		client.NewRequest(http.MethodGet, "/"),
	)
	require.NoErrorf(t, err, "err: %s", err)
	require.Equalf(t, newNS, ns, "Expected new namespace: %q, got %q", newNS, ns)

	// ensure client has not been modified
	_, err = client.rawRequestWithContext(
		t.Context(),
		client.NewRequest(http.MethodGet, "/"),
	)
	require.NoErrorf(t, err, "err: %s", err)
	require.Equalf(t, ogNS, ns, "Expected namespace: %q, got %q", ogNS, ns)

	// make call with empty ns
	_, err = client.WithNamespace("").rawRequestWithContext(
		t.Context(),
		client.NewRequest(http.MethodGet, "/"),
	)
	require.NoErrorf(t, err, "err: %s", err)
	require.Emptyf(t, ns, "Expected no namespace, got %q", ns)

	// ensure client has not been modified
	require.Equalf(t, ogNS, client.Namespace(), "Expected original namespace: %q, got %q", ogNS, client.Namespace())
}

func TestVaultProxy(t *testing.T) {
	const NoProxy string = "NO_PROXY"

	tests := map[string]struct {
		name                     string
		vaultHttpProxy           string
		vaultProxyAddr           string
		noProxy                  string
		requestUrl               string
		expectedResolvedProxyUrl string
	}{
		"BAO_HTTP_PROXY used when NO_PROXY env var doesn't include request host": {
			vaultHttpProxy: "https://hashicorp.com",
			vaultProxyAddr: "",
			noProxy:        "terraform.io",
			requestUrl:     "https://vaultproject.io",
		},
		"BAO_HTTP_PROXY used when NO_PROXY env var includes request host": {
			vaultHttpProxy: "https://hashicorp.com",
			vaultProxyAddr: "",
			noProxy:        "terraform.io,vaultproject.io",
			requestUrl:     "https://vaultproject.io",
		},
		"BAO_PROXY_ADDR used when NO_PROXY env var doesn't include request host": {
			vaultHttpProxy: "",
			vaultProxyAddr: "https://hashicorp.com",
			noProxy:        "terraform.io",
			requestUrl:     "https://vaultproject.io",
		},
		"BAO_PROXY_ADDR used when NO_PROXY env var includes request host": {
			vaultHttpProxy: "",
			vaultProxyAddr: "https://hashicorp.com",
			noProxy:        "terraform.io,vaultproject.io",
			requestUrl:     "https://vaultproject.io",
		},
		"BAO_PROXY_ADDR used when BAO_HTTP_PROXY env var also supplied": {
			vaultHttpProxy:           "https://hashicorp.com",
			vaultProxyAddr:           "https://terraform.io",
			noProxy:                  "",
			requestUrl:               "https://vaultproject.io",
			expectedResolvedProxyUrl: "https://terraform.io",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.vaultHttpProxy != "" {
				t.Setenv(EnvHTTPProxy, tc.vaultHttpProxy)
			}

			if tc.vaultProxyAddr != "" {
				t.Setenv(EnvVaultProxyAddr, tc.vaultProxyAddr)
			}

			if tc.noProxy != "" {
				t.Setenv(NoProxy, tc.noProxy)
			}

			c := DefaultConfig()
			require.NoErrorf(t, c.Error, "Expected no error reading config, found error %v", c.Error)

			r, _ := http.NewRequest("GET", tc.requestUrl, nil)
			proxyUrl, err := c.HttpClient.Transport.(*http.Transport).Proxy(r)
			require.NoErrorf(t, err, "Expected no error resolving proxy, found error %v", err)
			require.NotNil(t, proxyUrl)
			require.NotEmpty(t, proxyUrl.String())
			require.False(t, tc.expectedResolvedProxyUrl != "" && tc.expectedResolvedProxyUrl != proxyUrl.String())
		})
	}
}

func TestParseAddressWithUnixSocket(t *testing.T) {
	address := "unix:///var/run/vault.sock"
	config := DefaultConfig()

	u, err := config.ParseAddress(address)
	require.NoError(t, err, "Error not expected")
	require.Equal(t, "http", u.Scheme, "Scheme not changed to http")
	require.Equal(t, "localhost", u.Host, "Host not changed to socket name")
	require.Empty(t, u.Path, "Path expected to be blank")
	require.NotNil(t, config.HttpClient.Transport.(*http.Transport).DialContext, "DialContext function not set in config.HttpClient.Transport")
}
