// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//go:build blackbox

package http_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/configutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	. "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/internal/assert"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

const (
	BLANK = ""
)

func TestHandler_cors(t *testing.T) {
	core, _, _ := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	// Enable CORS and allow from any origin for testing.
	corsConfig := core.CORSConfig()
	err := corsConfig.Enable(t.Context(), []string{addr}, nil, false)
	assert.Ok(t, err, "Error enabling CORS: %s")

	req, err := http.NewRequest(http.MethodOptions, addr+"/v1/sys/seal-status", nil)
	assert.Ok(t, err)
	req.Header.Set("Origin", "BAD ORIGIN")

	// Requests from unacceptable origins will be rejected with a 403.
	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusForbidden)

	//
	// Test preflight requests
	//

	// Set a valid origin
	req.Header.Set("Origin", addr)

	// Server should NOT accept arbitrary methods.
	req.Header.Set("Access-Control-Request-Method", "FOO")

	client = cleanhttp.DefaultClient()
	resp, err = client.Do(req)
	assert.Ok(t, err)

	// Fail if an arbitrary method is accepted.
	assert.Equal(t, resp.StatusCode, http.StatusMethodNotAllowed)

	// Server SHOULD accept acceptable methods.
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)

	client = cleanhttp.DefaultClient()
	resp, err = client.Do(req)
	assert.Ok(t, err)

	//
	// Test that the CORS headers are applied correctly.
	//
	expHeaders := map[string]string{
		"Access-Control-Allow-Origin":  addr,
		"Access-Control-Allow-Headers": strings.Join(vault.StdAllowedHeaders, ","),
		"Access-Control-Max-Age":       "300",
		"Vary":                         "Origin",
	}

	for expHeader, expected := range expHeaders {
		actual := resp.Header.Get(expHeader)
		assert.NotEqual(t, actual, BLANK)

		assert.Equal(t, actual, expected)
	}

	// Test that the Access-Control-Allow-Credentials is set correctly when configured
	err = corsConfig.Enable(t.Context(), []string{addr}, nil, true)
	assert.Ok(t, err, "Error enabling CORS: %s")

	client = cleanhttp.DefaultClient()
	resp, err = client.Do(req)
	assert.Ok(t, err)

	expHeaders["Access-Control-Allow-Credentials"] = "true"

	for expHeader, expected := range expHeaders {
		actual := resp.Header.Get(expHeader)
		assert.NotEqual(t, actual, BLANK)

		assert.Equal(t, actual, expected)
	}
}

func TestHandler_HostnameHeader(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		description   string
		config        *vault.CoreConfig
		headerPresent bool
	}{
		{
			description:   "with no header configured",
			config:        nil,
			headerPresent: false,
		},
		{
			description: "with header configured",
			config: &vault.CoreConfig{
				EnableResponseHeaderHostname: true,
			},
			headerPresent: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			var core *vault.Core

			if tc.config == nil {
				core, _, _ = vault.TestCoreUnsealed(t)
			} else {
				core, _, _ = vault.TestCoreUnsealedWithConfig(t, tc.config)
			}

			ln, addr := TestServer(t, core)
			defer ln.Close()

			req, err := http.NewRequest("GET", addr+"/v1/sys/seal-status", nil)
			assert.Ok(t, err)

			client := cleanhttp.DefaultClient()
			resp, err := client.Do(req)
			assert.Ok(t, err)

			assert.NotNil(t, resp)

			hnHeader := resp.Header.Get(consts.HostnameHeaderName)
			if tc.headerPresent && hnHeader == BLANK {
				t.Logf("header configured = %t", core.HostnameHeaderEnabled())
				t.Fatal("missing 'X-Vault-Hostname' header entry in response")
			}
			if !tc.headerPresent && hnHeader != BLANK {
				t.Fatal("didn't expect 'X-Vault-Hostname' header but it was present anyway")
			}

			rniHeader := resp.Header.Get(consts.RaftNodeIDHeaderName)
			assert.Equal(t, rniHeader, BLANK, "no raft node ID header was expected, since we're not running a raft cluster. instead, got %s")
		})
	}
}

func TestHandler_CacheControlNoStore(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	req, err := http.NewRequest("GET", addr+"/v1/sys/mounts", nil)
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)
	req.Header.Set(consts.WrapTTLHeaderName, "60s")

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	assert.NotNil(t, resp)

	actual := resp.Header.Get("Cache-Control")

	assert.NotEqual(t, actual, BLANK)

	assert.Equal(t, actual, "no-store", "bad: Cache-Control. Expected: 'no-store', Actual: %q")
}

func TestHandler_InFlightRequest(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	req, err := http.NewRequest("GET", addr+"/v1/sys/in-flight-req", nil)
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	assert.NotNil(t, resp)

	var actual map[string]any
	assert.HttpStatusEqual(t, resp, 200)
	assert.HttpJsonResponse(t, resp, &actual)
	assert.NotEqual(t, len(actual), 0)
	for _, v := range actual {
		reqInfo, ok := v.(map[string]any)
		assert.Equal(t, ok, true, "Failed to read in-flight request")
		assert.Equal(t, reqInfo["request_path"], "/v1/sys/in-flight-req")
	}
}

// TestHandler_MissingToken tests the response / error code if a request comes
// in with a missing client token. See
// https://github.com/openbao/openbao/issues/8377
func TestHandler_MissingToken(t *testing.T) {
	// core, _, token := vault.TestCoreUnsealed(t)
	core, _, _ := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	req, err := http.NewRequest("GET", addr+"/v1/sys/internal/ui/mounts/cubbyhole", nil)
	assert.Ok(t, err)

	req.Header.Set(consts.WrapTTLHeaderName, "60s")

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)
	assert.Equal(t, resp.StatusCode, 403)
}

func TestHandler_Accepted(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	req, err := http.NewRequest("POST", addr+"/v1/auth/token/tidy", nil)
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	assert.HttpStatusEqual(t, resp, 202)
}

// We use this test to verify header auth
func TestSysMounts_headerAuth(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	req, err := http.NewRequest("GET", addr+"/v1/sys/mounts", nil)
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	var actual map[string]any
	expected := map[string]any{
		"lease_id":       BLANK,
		"renewable":      false,
		"lease_duration": json.Number("0"),
		"wrap_info":      nil,
		"warnings":       nil,
		"auth":           nil,
		"data": map[string]any{
			"secret/": map[string]any{
				"description":             "key/value secret storage",
				"type":                    "kv",
				"external_entropy_access": false,
				"config": map[string]any{
					"default_lease_ttl": json.Number("0"),
					"max_lease_ttl":     json.Number("0"),
					"force_no_cache":    false,
				},
				"local":                  false,
				"seal_wrap":              false,
				"options":                map[string]any{"version": "1"},
				"plugin_version":         BLANK,
				"running_sha256":         BLANK,
				"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "kv"),
				"deprecation_status":     "supported",
			},
			"sys/": map[string]any{
				"description":             "system endpoints used for control, policy and debugging",
				"type":                    "system",
				"external_entropy_access": false,
				"config": map[string]any{
					"default_lease_ttl":           json.Number("0"),
					"max_lease_ttl":               json.Number("0"),
					"force_no_cache":              false,
					"passthrough_request_headers": []any{"Accept"},
				},
				"local":                  false,
				"seal_wrap":              true,
				"options":                any(nil),
				"plugin_version":         BLANK,
				"running_sha256":         BLANK,
				"running_plugin_version": versions.DefaultBuiltinVersion,
			},
			"cubbyhole/": map[string]any{
				"description":             "per-token private secret storage",
				"type":                    "cubbyhole",
				"external_entropy_access": false,
				"config": map[string]any{
					"default_lease_ttl": json.Number("0"),
					"max_lease_ttl":     json.Number("0"),
					"force_no_cache":    false,
				},
				"local":                  true,
				"seal_wrap":              false,
				"options":                any(nil),
				"plugin_version":         BLANK,
				"running_sha256":         BLANK,
				"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole"),
			},
			"identity/": map[string]any{
				"description":             "identity store",
				"type":                    "identity",
				"external_entropy_access": false,
				"config": map[string]any{
					"default_lease_ttl":           json.Number("0"),
					"max_lease_ttl":               json.Number("0"),
					"force_no_cache":              false,
					"passthrough_request_headers": []any{"Authorization"},
				},
				"local":                  false,
				"seal_wrap":              false,
				"options":                any(nil),
				"plugin_version":         BLANK,
				"running_sha256":         BLANK,
				"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "identity"),
			},
		},
		"secret/": map[string]any{
			"description":             "key/value secret storage",
			"type":                    "kv",
			"external_entropy_access": false,
			"config": map[string]any{
				"default_lease_ttl": json.Number("0"),
				"max_lease_ttl":     json.Number("0"),
				"force_no_cache":    false,
			},
			"local":                  false,
			"seal_wrap":              false,
			"options":                map[string]any{"version": "1"},
			"plugin_version":         BLANK,
			"running_sha256":         BLANK,
			"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "kv"),
			"deprecation_status":     "supported",
		},
		"sys/": map[string]any{
			"description":             "system endpoints used for control, policy and debugging",
			"type":                    "system",
			"external_entropy_access": false,
			"config": map[string]any{
				"default_lease_ttl":           json.Number("0"),
				"max_lease_ttl":               json.Number("0"),
				"force_no_cache":              false,
				"passthrough_request_headers": []any{"Accept"},
			},
			"local":                  false,
			"seal_wrap":              true,
			"options":                any(nil),
			"plugin_version":         BLANK,
			"running_sha256":         BLANK,
			"running_plugin_version": versions.DefaultBuiltinVersion,
		},
		"cubbyhole/": map[string]any{
			"description":             "per-token private secret storage",
			"type":                    "cubbyhole",
			"external_entropy_access": false,
			"config": map[string]any{
				"default_lease_ttl": json.Number("0"),
				"max_lease_ttl":     json.Number("0"),
				"force_no_cache":    false,
			},
			"local":                  true,
			"seal_wrap":              false,
			"options":                any(nil),
			"plugin_version":         BLANK,
			"running_sha256":         BLANK,
			"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole"),
		},
		"identity/": map[string]any{
			"description":             "identity store",
			"type":                    "identity",
			"external_entropy_access": false,
			"config": map[string]any{
				"default_lease_ttl":           json.Number("0"),
				"max_lease_ttl":               json.Number("0"),
				"force_no_cache":              false,
				"passthrough_request_headers": []any{"Authorization"},
			},
			"local":                  false,
			"seal_wrap":              false,
			"options":                any(nil),
			"plugin_version":         BLANK,
			"running_sha256":         BLANK,
			"running_plugin_version": versions.GetBuiltinVersion(consts.PluginTypeSecrets, "identity"),
		},
	}
	assert.HttpStatusEqual(t, resp, 200)
	assert.HttpJsonResponse(t, resp, &actual)

	expected["request_id"] = actual["request_id"]
	for k, v := range actual["data"].(map[string]any) {
		data := v.(map[string]any)
		assert.NotEqual(t, data["accessor"], BLANK)
		assert.NotEqual(t, data["uuid"], BLANK)

		expected[k].(map[string]any)["accessor"] = v.(map[string]any)["accessor"]
		expected[k].(map[string]any)["uuid"] = v.(map[string]any)["uuid"]
		expected["data"].(map[string]any)[k].(map[string]any)["accessor"] = v.(map[string]any)["accessor"]
		expected["data"].(map[string]any)[k].(map[string]any)["uuid"] = v.(map[string]any)["uuid"]
	}

	if diff := deep.Equal(actual, expected); len(diff) > 0 {
		t.Fatalf("bad, diff: %#v", diff)
	}
}

// We use this test to verify header auth wrapping
func TestSysMounts_headerAuth_Wrapped(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	req, err := http.NewRequest("GET", addr+"/v1/sys/mounts", nil)
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)
	req.Header.Set(consts.WrapTTLHeaderName, "60s")

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	var actual map[string]any
	expected := map[string]any{
		"request_id":     BLANK,
		"lease_id":       BLANK,
		"renewable":      false,
		"lease_duration": json.Number("0"),
		"data":           nil,
		"wrap_info": map[string]any{
			"ttl": json.Number("60"),
		},
		"warnings": nil,
		"auth":     nil,
	}

	assert.HttpStatusEqual(t, resp, 200)
	assert.HttpJsonResponse(t, resp, &actual)

	actualToken, ok := actual["wrap_info"].(map[string]any)["token"]
	if !ok || actualToken == BLANK {
		t.Fatal("token missing in wrap info")
	}
	expected["wrap_info"].(map[string]any)["token"] = actualToken

	actualCreationTime, ok := actual["wrap_info"].(map[string]any)["creation_time"]
	if !ok || actualCreationTime == BLANK {
		t.Fatal("creation_time missing in wrap info")
	}
	expected["wrap_info"].(map[string]any)["creation_time"] = actualCreationTime

	actualCreationPath, ok := actual["wrap_info"].(map[string]any)["creation_path"]
	if !ok || actualCreationPath == BLANK {
		t.Fatal("creation_path missing in wrap info")
	}
	expected["wrap_info"].(map[string]any)["creation_path"] = actualCreationPath

	actualAccessor, ok := actual["wrap_info"].(map[string]any)["accessor"]
	if !ok || actualAccessor == BLANK {
		t.Fatal("accessor missing in wrap info")
	}
	expected["wrap_info"].(map[string]any)["accessor"] = actualAccessor

	assert.Equal(t, actual, expected)
}

func TestHandler_sealed(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	core.Seal(token)

	resp, err := http.Get(addr + "/v1/secret/foo")
	assert.Ok(t, err)
	assert.HttpStatusEqual(t, resp, 503)
}

func TestHandler_ui_default(t *testing.T) {
	core := vault.TestCoreUI(t, false)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	resp, err := http.Get(addr + "/ui/")
	assert.Ok(t, err)
	assert.HttpStatusEqual(t, resp, 404)
}

func TestHandler_ui_enabled(t *testing.T) {
	core := vault.TestCoreUI(t, true)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	resp, err := http.Get(addr + "/ui/")
	assert.Ok(t, err)
	assert.HttpStatusEqual(t, resp, 200)
}

func TestHandler_error(t *testing.T) {
	w := httptest.NewRecorder()

	assert.HttpErrorResponse(w, 500, errors.New("test Error"))

	assert.Equal(t, w.Code, 500)

	// The code inside of the error should override
	// the argument to respondError
	w2 := httptest.NewRecorder()
	e := logical.CodedError(403, "error text")

	assert.HttpErrorResponse(w2, 500, e)

	assert.Equal(t, w2.Code, 403)

	// vault.ErrSealed is a special case
	w3 := httptest.NewRecorder()

	assert.HttpErrorResponse(w3, 400, consts.ErrSealed)

	assert.Equal(t, w3.Code, 503)
}

func TestHandler_nonPrintableChars(t *testing.T) {
	testNonPrintable(t, false)
	testNonPrintable(t, true)
}

func testNonPrintable(t *testing.T, disable bool) {
	core, _, token := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		DisableKeyEncodingChecks: disable,
	})
	ln, addr := TestListener(t)
	props := &vault.HandlerProperties{
		Core:                  core,
		DisablePrintableCheck: disable,
	}
	TestServerWithListenerAndProperties(t, ln, addr, core, props)
	defer ln.Close()

	req, err := http.NewRequest("PUT", addr+"/v1/cubbyhole/foo\u2028bar", strings.NewReader(`{"zip": "zap"}`))
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)

	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	assert.Ok(t, err)

	if disable {
		assert.HttpStatusEqual(t, resp, 204)
	} else {
		assert.HttpStatusEqual(t, resp, 400)
	}
}

func TestHandler_Parse_Form(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	core := cores[0].Core
	vault.TestWaitActive(t, core)

	c := cleanhttp.DefaultClient()
	c.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: cluster.RootCAs,
		},
	}

	values := url.Values{
		"zip":   []string{"zap"},
		"abc":   []string{"xyz"},
		"multi": []string{"first", "second"},
		"empty": []string{},
	}
	req, err := http.NewRequest("POST", cores[0].Client.Address()+"/v1/secret/foo", nil)
	assert.Ok(t, err)
	req.Body = io.NopCloser(strings.NewReader(values.Encode()))
	req.Header.Set("x-vault-token", cluster.RootToken)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	assert.Ok(t, err)

	assert.HttpStatusEqual(t, resp, 204)

	client := cores[0].Client
	client.SetToken(cluster.RootToken)

	apiResp, err := client.Logical().Read("secret/foo")
	assert.Ok(t, err)
	assert.NotNil(t, apiResp)
	expected := map[string]any{
		"zip":   "zap",
		"abc":   "xyz",
		"multi": "first,second",
	}
	if diff := deep.Equal(expected, apiResp.Data); diff != nil {
		t.Fatal(diff)
	}
}

// TestHandler_MaxRequestSize verifies that a request larger than the
// MaxRequestSize fails
func TestHandler_MaxRequestSize(t *testing.T) {
	t.Parallel()
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		DefaultHandlerProperties: vault.HandlerProperties{
			ListenerConfig: &configutil.Listener{
				MaxRequestSize: 1024,
			},
		},
		HandlerFunc: Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	_, err := client.KVv2("secret").Put(t.Context(), "foo", map[string]any{
		"bar": strings.Repeat("a", 1025),
	})

	var respErr *api.ResponseError
	assert.ErrorAs(t, err, &respErr)
	assert.Equal(t, respErr.StatusCode, http.StatusRequestEntityTooLarge)
	assert.Equal(t, strings.Contains(err.Error(), "request body too large"), true)
}

// TestHandler_MaxRequestSize_Memory sets the max request size to 1024 bytes,
// and creates a 1MB request. The test verifies that less than 1MB of memory is
// allocated when the request is sent. This test shouldn't be run in parallel,
// because it modifies GOMAXPROCS
func TestHandler_MaxRequestSize_Memory(t *testing.T) {
	ln, addr := TestListener(t)
	core, _, token := vault.TestCoreUnsealed(t)
	TestServerWithListenerAndProperties(t, ln, addr, core, &vault.HandlerProperties{
		Core: core,
		ListenerConfig: &configutil.Listener{
			Address:        addr,
			MaxRequestSize: 1024,
		},
	})
	defer ln.Close()

	data := bytes.Repeat([]byte{0x1}, 1024*1024)

	req, err := http.NewRequest("POST", addr+"/v1/sys/unseal", bytes.NewReader(data))
	assert.Ok(t, err)
	req.Header.Set(consts.AuthHeaderName, token)

	client := cleanhttp.DefaultClient()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	var start, end runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&start)
	client.Do(req)
	runtime.ReadMemStats(&end)
	size := end.TotalAlloc - start.TotalAlloc
	limit := uint64(1024 * 1024)
	assert.Equal(t, size < limit, true)
}

func TestHandler_RestrictedEndpointCalls(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	// add namespaces for tests
	vault.TestCoreCreateNamespaces(t, core,
		&namespace.Namespace{Path: "test"},
		&namespace.Namespace{Path: "test/test2"},
	)

	tests := []struct {
		name            string
		method          string
		path            string
		namespaceHeader string

		expectedStatusCode int
	}{
		{
			name:               "happy path - root namespace quota call",
			method:             "GET",
			path:               "/v1/sys/quotas/rate-limit?list=true",
			expectedStatusCode: 404,
		},
		{
			name:               "happy path - root namespace quota call through sys-raw",
			method:             "GET",
			path:               "/v1/sys/raw/sys/quotas/rate-limit?list=true",
			expectedStatusCode: 404,
		},
		{
			name:               "bad path - namespace in path request",
			method:             "GET",
			path:               "/v1/test/sys/quotas/rate-limit?list=true",
			expectedStatusCode: 400,
		},
		{
			name:               "bad path - namespace in header request",
			method:             "GET",
			path:               "/v1/sys/quotas/rate-limit?list=true",
			namespaceHeader:    "test",
			expectedStatusCode: 400,
		},
		{
			name:               "bad path - namespace in both header and path request",
			method:             "GET",
			path:               "/v1/test2/sys/quotas/rate-limit?list=true",
			namespaceHeader:    "test",
			expectedStatusCode: 400,
		},
		{
			name:               "bad path - namespace at the beginning path request through sys-raw",
			method:             "GET",
			path:               "/v1/test/sys/raw/sys/quotas/rate-limit?list=true",
			expectedStatusCode: 400,
		},
		{
			name:               "bad path - namespace in header passed for request through sys-raw",
			method:             "GET",
			path:               "/v1/sys/raw/sys/quotas/rate-limit?list=true",
			namespaceHeader:    "test",
			expectedStatusCode: 400,
		},
		{
			name:               "bad path - namespace in both header and path passed for request through sys-raw",
			method:             "GET",
			path:               "/v1/test2/sys/raw/sys/quotas/rate-limit?list=true",
			namespaceHeader:    "test",
			expectedStatusCode: 400,
		},
		{
			name:               "happy path - root can create policy with restricted name",
			method:             "PUT",
			path:               "/v1/sys/policies/acl/sys/raw",
			expectedStatusCode: 204,
		},
		{
			name:               "happy path - namespace (path) can create policy with restricted name",
			method:             "PUT",
			path:               "/v1/test/sys/policies/acl/sys/raw",
			expectedStatusCode: 204,
		},
		{
			name:               "happy path - namespace (header) can create policy with restricted name",
			method:             "PUT",
			path:               "/v1/sys/policies/acl/sys/raw",
			namespaceHeader:    "test",
			expectedStatusCode: 204,
		},
		{
			name:               "happy path - namespace (path & header) can create policy with restricted name",
			method:             "PUT",
			path:               "/v1/test2/sys/policies/acl/sys/raw",
			namespaceHeader:    "test",
			expectedStatusCode: 204,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, addr := TestServer(t, core)
			defer ln.Close()

			var body io.Reader
			if tt.method == "PUT" {
				bodyString := `{"policy":"path \"auth/token/lookup\" {\n capabilities = [\"read\", \"update\"]\n}\n\npath \"*/auth/token/lookup\" {\n capabilities = [\"read\", \"update\"]\n}"}`
				body = bytes.NewBufferString(bodyString)
			}
			req, err := http.NewRequest(tt.method, addr+tt.path, body)
			assert.Ok(t, err)

			req.Header.Set(consts.AuthHeaderName, token)
			req.Header.Set(consts.NamespaceHeaderName, tt.namespaceHeader)
			client := cleanhttp.DefaultClient()
			client.Timeout = 60 * time.Second

			res, err := client.Do(req)
			assert.Ok(t, err)
			assert.Equal(t, tt.expectedStatusCode, res.StatusCode)
		})
	}
}
