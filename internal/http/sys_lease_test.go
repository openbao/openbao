// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestSysRenew(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	// write secret
	resp := testHttpPut(t, token, addr+"/v1/secret/foo", map[string]any{
		"data":  "bar",
		"lease": "1h",
	})
	testResponseStatus(t, resp, 204)

	// read secret
	resp = testHttpGet(t, token, addr+"/v1/secret/foo")
	var result struct {
		LeaseID string `json:"lease_id"`
	}
	require.NoError(t, jsonutil.DecodeJSONFromReader(resp.Body, &result))

	var renewResult struct {
		LeaseID string         `json:"lease_id"`
		Data    map[string]any `json:"data"`
	}

	resp = testHttpPut(t, token, addr+"/v1/sys/leases/renew/"+result.LeaseID, nil)
	testResponseStatus(t, resp, 200)
	require.NoError(t, jsonutil.DecodeJSONFromReader(resp.Body, &renewResult))
	if result.LeaseID != renewResult.LeaseID {
		t.Fatal("lease id changed in renew request")
	}
}

func TestSysRevoke(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	resp := testHttpPut(t, token, addr+"/v1/sys/leases/revoke/secret/foo/1234", nil)
	testResponseStatus(t, resp, 204)
}

func TestSysRevokePrefix(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	resp := testHttpPut(t, token, addr+"/v1/sys/leases/revoke-prefix/secret/foo/1234", nil)
	testResponseStatus(t, resp, 204)
}
