// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/hashicorp/consul-template/test"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userAgent = "my-user-agent"

func TestClientSet_K8SServiceTokenAuth(t *testing.T) {
	t.Parallel()

	validSecret := &api.Secret{Auth: &api.SecretAuth{ClientToken: vaultToken}}
	invalidSecret := &api.Secret{Auth: &api.SecretAuth{ClientToken: "invalid"}}
	require.NotEqual(t, validSecret, invalidSecret)

	k8sLoginPathCond := func(mountPath string) func(r *http.Request) bool {
		return func(r *http.Request) bool {
			return r.URL.Path == "/v1/auth/"+mountPath+"/login"
		}
	}

	t.Run("service_token_value", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t, vaultMock{
			HandleCond: k8sLoginPathCond("kubernetes"),
			HandleJSON: func(_ *http.Request, data map[string]interface{}) interface{} {
				assert.Equal(t, data["jwt"], "service_token", data)
				assert.Equal(t, data["role"], "default", data)

				return validSecret
			},
		})

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                testServerAddr,
			ClientUserAgent:        userAgent,
			K8SAuthRoleName:        "default",
			K8SServiceAccountToken: "service_token",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = clientSet.Vault().Logical().List("/entities")
		require.NoError(t, err)
	})

	t.Run("service_token_from_file", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t, vaultMock{
			HandleCond: k8sLoginPathCond("kubernetes"),
			HandleJSON: func(_ *http.Request, data map[string]interface{}) interface{} {
				assert.Equal(t, data["jwt"], "service_token", data)
				assert.Equal(t, data["role"], "default_file", data)

				return validSecret
			},
		})

		f := test.CreateTempfile(t, []byte("service_token"))

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                    testServerAddr,
			ClientUserAgent:            userAgent,
			K8SAuthRoleName:            "default_file",
			K8SServiceAccountTokenPath: f.Name(),
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = clientSet.Vault().Logical().List("/entities")
		require.NoError(t, err)
	})

	t.Run("service_token_file_value_priority", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t, vaultMock{
			HandleCond: k8sLoginPathCond("kubernetes"),
			HandleJSON: func(_ *http.Request, data map[string]interface{}) interface{} {
				assert.Equal(t, data["jwt"], "service_token_value", data)
				assert.Equal(t, data["role"], "default", data)

				return validSecret
			},
		})

		f := test.CreateTempfile(t, []byte("service_token_file"))

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                    testServerAddr,
			ClientUserAgent:            userAgent,
			K8SAuthRoleName:            "default",
			K8SServiceAccountTokenPath: f.Name(),
			K8SServiceAccountToken:     "service_token_value",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = clientSet.Vault().Logical().List("/entities")
		require.NoError(t, err)
	})

	t.Run("mount_path", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t, vaultMock{
			HandleCond: k8sLoginPathCond("mount_path"),
			HandleJSON: func(r *http.Request, data map[string]interface{}) interface{} {
				return validSecret
			},
		})

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                testServerAddr,
			ClientUserAgent:        userAgent,
			K8SAuthRoleName:        "default",
			K8SServiceAccountToken: "service_token",
			K8SServiceMountPath:    "mount_path",
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = clientSet.Vault().Logical().List("/entities")
		require.NoError(t, err)
	})

	t.Run("token_already_set", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t)

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                testServerAddr,
			ClientUserAgent:        userAgent,
			Token:                  vaultToken,
			K8SAuthRoleName:        "default",
			K8SServiceAccountToken: "service_token",
		})
		require.NoError(t, err)

		_, err = clientSet.Vault().Logical().List("/entities")
		require.NoError(t, err)
	})

	t.Run("auth_failed", func(t *testing.T) {
		t.Parallel()

		testServerAddr := newVaultMockReversedProxy(t, vaultMock{
			HandleCond: k8sLoginPathCond("kubernetes"),
			HandleJSON: func(*http.Request, map[string]interface{}) interface{} {
				return invalidSecret
			},
		})

		clientSet := NewClientSet()
		err := clientSet.CreateVaultClient(&CreateVaultClientInput{
			Address:                testServerAddr,
			ClientUserAgent:        userAgent,
			K8SAuthRoleName:        "default",
			K8SServiceAccountToken: "service_token",
		})
		require.NoError(t, err)

		_, err = clientSet.Vault().Logical().List("/entities")
		require.Error(t, err)
	})
}

type vaultMock struct {
	HandleCond func(r *http.Request) bool
	HandleJSON func(r *http.Request, data map[string]interface{}) interface{}
}

func (m vaultMock) processReq(tb testing.TB, w http.ResponseWriter, r *http.Request) {
	if m.HandleJSON == nil {
		return
	}

	if r.UserAgent() != userAgent {
		tb.Fatalf("User-Agent header not as expected. Expected %s, got %s. Request was to %s", userAgent, r.UserAgent(), r.RequestURI)
	}

	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if !assert.NoError(tb, err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	tb.Logf("%s: %s: %+v", r.Method, r.URL, data)

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(m.HandleJSON(r, data))
	assert.NoError(tb, err)
}

// newVaultMockReversedProxy mocks some calls and proxies others to Vault.
func newVaultMockReversedProxy(tb testing.TB, mocks ...vaultMock) string {
	tb.Helper()

	vaultURL, err := url.Parse(vaultAddr)
	require.NoError(tb, err)

	vaultReverseProxy := httputil.NewSingleHostReverseProxy(vaultURL)

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			for _, m := range mocks {
				if !m.HandleCond(r) {
					continue
				}

				m.processReq(tb, w, r)

				return
			}

			vaultReverseProxy.ServeHTTP(w, r)
		}),
	)
	tb.Cleanup(testServer.Close)

	return testServer.URL
}
