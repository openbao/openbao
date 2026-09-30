// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"sync"
	"testing"

	log "github.com/hashicorp/go-hclog"
	auth "github.com/openbao/openbao/api/auth/approle/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	credAppRole "github.com/openbao/openbao/v2/internal/builtin/credential/approle"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestAppRole_Integ_ConcurrentLogins(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
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

	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("auth/approle/role/role1", map[string]any{
		"bind_secret_id": "true",
		"period":         "300",
	})
	require.NoError(t, err)

	secret, err := client.Logical().Write("auth/approle/role/role1/secret-id", nil)
	require.NoError(t, err)
	secretID := secret.Data["secret_id"].(string)

	secret, err = client.Logical().Read("auth/approle/role/role1/role-id")
	require.NoError(t, err)
	roleID := secret.Data["role_id"].(string)

	wg := &sync.WaitGroup{}

	for range 100 {
		wg.Go(func() {
			appRoleAuth, err := auth.NewAppRoleAuth(roleID, &auth.SecretID{FromString: secretID})
			if err != nil {
				t.Error(err)
				return
			}
			secret, err := client.Auth().Login(t.Context(), appRoleAuth)
			if err != nil {
				t.Error(err)
				return
			}
			if secret.Auth.ClientToken == "" {
				t.Error("expected a successful login")
				return
			}
		})
	}
	wg.Wait()
}
