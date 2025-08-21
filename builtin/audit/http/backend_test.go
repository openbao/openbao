// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func getAuditHandler(t *testing.T, lock *sync.Mutex, logs *[]map[string]interface{}, path string, requiredHeaders http.Header, badRequests *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		t.Logf("got request: %#v", r)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.URL.Path != path {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		for header, allowedValues := range requiredHeaders {
			actualValues := r.Header.Values(header)
			if len(actualValues) == 0 {
				t.Logf("missing expected header: %v", header)
				*badRequests += 1
				w.WriteHeader(http.StatusForbidden)
				return
			}

			for _, value := range actualValues {
				var found bool
				for _, allowedValue := range allowedValues {
					if allowedValue == value {
						found = true
					}
				}

				if !found {
					t.Logf("value %v is not allowed for header %v", value, header)
					*badRequests += 1
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}

		var log map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&log); err != nil {
			t.Logf("failed to decode request: %v", err)
			*badRequests += 1
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		*logs = append(*logs, log)
		t.Logf("adding log: %v", log)

		w.WriteHeader(http.StatusOK)
	}
}

func TestAuditHttp_Integration(t *testing.T) {
	var lock sync.Mutex
	var badRequests int
	logs := []map[string]interface{}{}
	logRoute := "/audit"

	testServer := httptest.NewServer(getAuditHandler(t, &lock, &logs, logRoute, nil, &badRequests))
	defer testServer.Close()

	url := testServer.URL + logRoute

	backend, err := Factory(context.Background(), &audit.BackendConfig{
		SaltConfig: &salt.Config{},
		SaltView:   &logical.InmemStorage{},
		Config: map[string]string{
			"uri": url,
		},
	})

	// We expect all test cases to be rejected.
	require.NoError(t, err)

	in := &logical.LogInput{
		Auth: &logical.Auth{
			ClientToken:     "foo",
			Accessor:        "bar",
			EntityID:        "foobarentity",
			DisplayName:     "testtoken",
			NoDefaultPolicy: true,
			Policies:        []string{"root"},
			TokenType:       logical.TokenTypeService,
		},
		Request: &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "/foo",
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
			WrapInfo: &logical.RequestWrapInfo{
				TTL: 60 * time.Second,
			},
			Headers: map[string][]string{
				"foo": {"bar"},
			},
		},
	}

	ctx := namespace.RootContext(context.Background())
	err = backend.LogRequest(ctx, in)
	require.NoError(t, err)

	require.Equal(t, badRequests, 0)

	lock.Lock()
	defer lock.Unlock()

	require.Equal(t, 1, len(logs))
	require.Contains(t, logs[0], "request")

	request := logs[0]["request"].(map[string]interface{})
	require.Contains(t, request, "path")
	require.Equal(t, request["path"].(string), "/foo")
}
