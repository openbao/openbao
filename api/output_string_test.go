// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strings"
	"testing"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
)

func newTestRequest(method, rawurl string, headers map[string]string, body string) *retryablehttp.Request {
	req, _ := retryablehttp.NewRequest(method, rawurl, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestOutputStringError_CurlStringAndError(t *testing.T) {
	testCases := []struct {
		name       string
		method     string
		url        string
		headers    map[string]string
		body       string
		skipTLS    bool
		cacert     string
		capath     string
		cert       string
		key        string
		wantSubstr []string
	}{
		{
			name:    "GET request with Vault token",
			method:  http.MethodGet,
			url:     "https://example.com/foo",
			headers: map[string]string{AuthHeaderName: "abcd1234"},
			wantSubstr: []string{
				`curl `,
				`-H "X-Vault-Token: $(bao print token)"`,
				`"https://example.com/foo"`,
			},
		},
		{
			name:    "POST request with JSON body",
			method:  http.MethodPost,
			url:     "https://api.test/path",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"name":"John's vault"}`,
			wantSubstr: []string{
				`-X POST`,
				`-d '{"name":"John'"'"'s vault"}'`,
				`"https://api.test/path"`,
			},
		},
		{
			name:    "TLS config with insecure and certs",
			method:  http.MethodGet,
			url:     "https://secure.com",
			skipTLS: true,
			cacert:  "/etc/ssl/my'ca.pem",
			capath:  "/etc/ssl/capath",
			cert:    "/etc/ssl/cert.pem",
			key:     "/etc/ssl/key.pem",
			wantSubstr: []string{
				`--insecure`,
				`--cacert '/etc/ssl/my'"'"'ca.pem'`,
				`--capath '/etc/ssl/capath'`,
				`--cert '/etc/ssl/cert.pem'`,
				`--key '/etc/ssl/key.pem'`,
				`"https://secure.com"`,
			},
		},
		{
			name:   "Error output",
			method: http.MethodGet,
			url:    "https://cached.com",
			wantSubstr: []string{
				`curl `,
				`"https://cached.com"`,
			},
		},
		{
			name:   "Nil request",
			method: http.MethodGet,
			url:    "https://nilrequest.com",
			wantSubstr: []string{
				`curl `,
				`"https://nilrequest.com"`,
			},
		},
		{
			name:   "Empty URL",
			method: http.MethodGet,
			url:    "",
			wantSubstr: []string{
				`curl `,
			},
		},
		{
			name:    "Missing headers",
			method:  http.MethodGet,
			url:     "https://missingheaders.com",
			headers: nil,
			wantSubstr: []string{
				`curl `,
				`"https://missingheaders.com"`,
			},
		},
		{
			name:    "Invalid TLS configuration",
			method:  http.MethodGet,
			url:     "https://invalidtls.com",
			skipTLS: true,
			cacert:  "/etc/ssl/invalid_ca.pem",
			capath:  "/etc/ssl/capath",
			cert:    "/etc/ssl/cert.pem",
			key:     "/etc/ssl/key.pem",
			wantSubstr: []string{
				`--insecure`,
				`--cacert '/etc/ssl/invalid_ca.pem'`,
				`"https://invalidtls.com"`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := newTestRequest(tc.method, tc.url, tc.headers, tc.body)
			ose := &OutputStringError{
				Request:       req,
				TLSSkipVerify: tc.skipTLS,
				ClientCACert:  tc.cacert,
				ClientCAPath:  tc.capath,
				ClientCert:    tc.cert,
				ClientKey:     tc.key,
			}

			out1, err1 := ose.CurlString()
			assert.NoError(t, err1)
			for _, substr := range tc.wantSubstr {
				assert.Contains(t, out1, substr)
			}
			assert.Equal(t, ErrOutputStringRequest, ose.Error())
		})
	}
}
