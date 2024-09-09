// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	credAppRole "github.com/openbao/openbao/builtin/credential/approle"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestAppRole_AliasNameFromLoginRequest_Panic(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"approle": credAppRole.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client
	client.SetToken(cluster.RootToken)

	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   make(map[string]interface{}),
		"secret_id": "",
	})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "INTERNAL_ERROR")
}
