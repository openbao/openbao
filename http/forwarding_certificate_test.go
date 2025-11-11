// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/vault"
)

// Reuse the test fixtures from the cert credential handler
const testCertPath1 = "../builtin/credential/cert/test-fixtures/testissuedcert4.pem"

func getTestHandler(decoders []string) func(props *vault.HandlerProperties) http.Handler {
	return func(props *vault.HandlerProperties) http.Handler {
		origHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write out what we internally processed.
			w.Header().Set("X-Processed-Tls-Client-Certificate-Resp", r.Header.Get("X-Processed-Tls-Client-Certificate"))
			w.WriteHeader(http.StatusOK)
		})
		listenerConfig := getListenerConfigForClientCerts(decoders)
		return WrapClientCertificateHandler(origHandler, listenerConfig)
	}
}

func getListenerConfigForClientCerts(decoders []string) *configutil.Listener {
	return &configutil.Listener{
		XForwardedForClientCertHeader:   "X-Forwarded-For-Client-Cert",
		XForwardedForClientCertDecoders: decoders,
	}
}

func TestHandler_XForwardedForClientCert(t *testing.T) {
	// Custom error name to prevent shadowing.
	clientCertFile, certErr := os.ReadFile(testCertPath1)
	if certErr != nil {
		t.Fatal(certErr)
	}
	clientCertBlock, _ := pem.Decode(clientCertFile)
	if clientCertBlock == nil || clientCertBlock.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode test client certificate")
	}
	clientCertPemText := string(clientCertFile)
	clientCertBase64 := base64.StdEncoding.EncodeToString(clientCertBlock.Bytes)

	t.Run("invalid_base64", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()

		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		req.Headers.Add("X-Forwarded-For-Client-Cert", "invalid")
		resp, err := client.RawRequest(req)
		if err == nil {
			t.Fatal("expected error")
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatal("failed to close response body")
			}
		}(resp.Body)
		buf := bytes.NewBuffer(nil)
		_, err = buf.ReadFrom(resp.Body)
		if err != nil {
			t.Fatal("failed to read response body")
		}
		if !strings.Contains(buf.String(), "error decoding client certificate header as base64") {
			t.Fatalf("bad body: %s", buf.String())
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != "" {
			t.Fatal("client certificate header should not have been set")
		}
	})

	t.Run("valid_base64", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		req.Headers.Add("X-Forwarded-For-Client-Cert", clientCertBase64)
		resp, err := client.RawRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad status: %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != clientCertBase64 {
			t.Fatal("mismatched client certificate response")
		}
	})

	// This will not work for some reason. Go refuses the header even when encoded with /r/n and with leading tabs.
	t.Run("nginx_ssl_client_cert_fails", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{"PEM"})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		// NGINX Prepends a tab before every line except the first
		// https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_cert
		clientCertPemTextHeader := strings.ReplaceAll(clientCertPemText, "\n", "\r\n\t")
		req.Headers.Add("X-Forwarded-For-Client-Cert", clientCertPemTextHeader)
		_, err := client.RawRequest(req)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "net/http: invalid header field value for \"X-Forwarded-For-Client-Cert\"") {
			t.Fatalf("bad error: %s", err)
		}
	})

	// https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert
	t.Run("nginx_ssl_client_escaped_cert", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{"URL", "PEM"})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)

		// NGINX urlencodes the certificate
		req.Headers.Add("X-Forwarded-For-Client-Cert", url.QueryEscape(clientCertPemText))
		resp, err := client.RawRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad status: %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != clientCertBase64 {
			t.Fatal("mismatched client certificate response")
		}
	})

	t.Run("invalid_pem_header", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{"URL", "PEM"})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		invalidPem := strings.ReplaceAll(clientCertPemText, "CERTIFICATE", "INVALID")
		req.Headers.Add("X-Forwarded-For-Client-Cert", url.QueryEscape(invalidPem))
		resp, err := client.RawRequest(req)
		if err == nil {
			t.Fatal("expected error")
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatal("failed to close response body")
			}
		}(resp.Body)
		buf := bytes.NewBuffer(nil)
		_, err = buf.ReadFrom(resp.Body)
		if err != nil {
			t.Fatal("failed to read response body")
		}
		if !strings.Contains(buf.String(), "failed to decode PEM certificate") {
			t.Fatalf("bad body: %s", buf.String())
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != "" {
			t.Fatal("client certificate header should not have been set")
		}
	})

	t.Run("invalid_escaped_cert", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{"URL", "PEM"})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		urlencodedCert := url.QueryEscape(clientCertPemText)
		// Encode with invalid hex
		urlencodedCert += "%GG"
		req.Headers.Add("X-Forwarded-For-Client-Cert", urlencodedCert)
		resp, err := client.RawRequest(req)
		if err == nil {
			t.Fatal("expected error")
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatal("failed to close response body")
			}
		}(resp.Body)
		buf := bytes.NewBuffer(nil)
		_, err = buf.ReadFrom(resp.Body)
		if err != nil {
			t.Fatal("failed to read response body")
		}
		if !strings.Contains(buf.String(), "error decoding client certificate header") {
			t.Fatalf("bad body: %s", buf.String())
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != "" {
			t.Fatal("client certificate header should not have been set")
		}
	})

	t.Run("no_header", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		resp, err := client.RawRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad status: %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != "" {
			t.Fatal("client certificate header should not have been set")
		}
	})

	t.Run("inject_processed_header", func(t *testing.T) {
		t.Parallel()
		testHandler := getTestHandler([]string{})
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			HandlerFunc: HandlerFunc(testHandler),
		})
		cluster.Start()
		defer cluster.Cleanup()
		client := cluster.Cores[0].Client
		req := client.NewRequest("GET", "/")
		req.Headers = make(http.Header)
		// Intentionally use the wrong canonical name.
		req.Headers.Add("X-Processed-TLS-Client-Certificate", clientCertBase64)
		resp, err := client.RawRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatal("failed to close response body")
			}
		}(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad status: %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Processed-Tls-Client-Certificate-Resp") != "" {
			t.Fatal("client certificate header should not have been set")
		}
	})
}
