// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestCORSPreflight_Methods(t *testing.T) {
	core, _, _ := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	origin := "https://test/"
	err := core.CORSConfig().Enable(t.Context(), []string{origin}, nil, false)
	require.NoError(t, err)

	methods := []string{
		"DELETE", "GET", "HEAD", "HELP", "LIST",
		"OPTIONS", "PATCH", "POST", "PUT", "SCAN",
	}

	for _, method := range append(methods, http.MethodTrace) {
		req, err := http.NewRequest(http.MethodOptions, addr+"/v1/sys/health", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", method)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		if method == http.MethodTrace {
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			continue
		}

		require.Equal(t, http.StatusOK, resp.StatusCode, method)
		require.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
		require.Subset(t, strings.Split(resp.Header.Get("Access-Control-Allow-Methods"), ","), methods)
	}
}
