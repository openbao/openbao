// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
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

func TestAuditHttp_Integration(t *testing.T) {
	var lock sync.Mutex
	var badRequests int
	logs := []map[string]interface{}{}
	logRoute := "/audit"

	requiredHeaders := http.Header{}
	requiredHeaders.Add("X-Gitlab-Openbao-Token", "foobarfud")

	testServer := httptest.NewServer(GetTestAuditHandler(t, &lock, &logs, logRoute, requiredHeaders, &badRequests))
	defer testServer.Close()

	url := testServer.URL + logRoute

	backend, err := Factory(context.Background(), &audit.BackendConfig{
		SaltConfig: &salt.Config{},
		SaltView:   &logical.InmemStorage{},
		Config: map[string]string{
			"uri":     url,
			"headers": `{"Content-Type":["application/json"],"Accept":["application/json"],"X-Gitlab-Openbao-Token":["foobarfud"]}`,
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
