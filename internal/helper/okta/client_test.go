// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package okta

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	setup := func(t *testing.T, handler http.Handler) *Client {
		t.Helper()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "SSWS okta-token", r.Header.Get("Authorization"))
			handler.ServeHTTP(w, r)
		}))
		server.Start()

		url, err := url.Parse(server.URL)
		require.NoError(t, err)

		// Slightly hacky, we assume "0.0.1" to be the Okta server's base domain
		// and "127" to be out organization's subdomain.
		client, err := New("0.0.1:"+url.Port(), "127", "okta-token")
		require.NoError(t, err)
		client.url.Scheme = "http"

		return client
	}

	t.Run("ListUsers", func(t *testing.T) {
		const filter = `profile.login eq "foo"`
		client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/api/v1/users", r.URL.Path)
			assert.Equal(t, filter, r.URL.Query().Get("filter"))
			_, err := w.Write([]byte(`[{ "id": "foo" }]`))
			assert.NoError(t, err)
		}))
		users, err := client.ListUsers(t.Context(), filter)
		require.NoError(t, err)
		require.Equal(t, []User{{ID: "foo"}}, users)
	})

	t.Run("ListFactors", func(t *testing.T) {
		client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/api/v1/users/foo/factors", r.URL.Path)
			_, err := w.Write([]byte(`[{ "id": "bar", "factorType": "push" }]`))
			assert.NoError(t, err)
		}))
		factors, err := client.ListFactors(t.Context(), "foo")
		require.NoError(t, err)
		require.Equal(t, []Factor{{ID: "bar", FactorType: "push"}}, factors)
	})

	t.Run("VerifyFactor", func(t *testing.T) {
		client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/api/v1/users/foo/factors/bar/verify", r.URL.Path)
			_, err := w.Write([]byte(`{ "factorResult": "WAITING", "_links": { "poll": { "href": "https://example.com" } } }`))
			assert.NoError(t, err)
		}))
		vfc, err := client.VerifyFactor(t.Context(), "foo", "bar")
		require.NoError(t, err)
		require.Equal(t, "WAITING", vfc.FactorResult)
		require.Equal(t, "https://example.com", vfc.Links.Poll.Href)
	})

	t.Run("Poll", func(t *testing.T) {
		client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/some/path/to/poll", r.URL.Path)
			_, err := w.Write([]byte(`{ "factorResult": "SUCCESS" }`))
			assert.NoError(t, err)
		}))
		t.Run("Path", func(t *testing.T) {
			vfc, err := client.Poll(t.Context(), "some/path/to/poll")
			require.NoError(t, err)
			require.Equal(t, "SUCCESS", vfc.FactorResult)
		})
		t.Run("URL", func(t *testing.T) {
			vfc, err := client.Poll(t.Context(), client.url.String()+"/some/path/to/poll")
			require.NoError(t, err)
			require.Equal(t, "SUCCESS", vfc.FactorResult)
		})
	})

	t.Run("Error", func(t *testing.T) {
		t.Run("Code", func(t *testing.T) {
			client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			}))
			_, err := client.ListUsers(t.Context(), "")
			require.ErrorContains(t, err, "unexpected status code 400")
		})
		t.Run("Summary", func(t *testing.T) {
			client := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(`{ "errorSummary": "this is bad" }`))
				assert.NoError(t, err)
			}))
			_, err := client.ListUsers(t.Context(), "")
			require.ErrorContains(t, err, "this is bad")
		})
	})
}
