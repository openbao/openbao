// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package namespaces

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceRepeatedDeletion(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Creation of 500 KV+userpass objects causes context cancellation timeouts in CI")
	}

	t.Parallel()

	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		EnableRaw:    true,
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"kv-v2": logicalKv.Factory,
			"kv-v1": logicalKv.Factory,
			"kv":    logicalKv.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    2,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	nsResp, err := client.Logical().Write("sys/namespaces/ns1", map[string]any{})
	require.NoError(t, err)
	require.NotNil(t, nsResp)
	require.Contains(t, nsResp.Data, "uuid")

	nsId := nsResp.Data["uuid"]

	ns1Client := client.WithNamespace("ns1")
	err = ns1Client.Sys().PutPolicy("admin", adminPolicy)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			populateMounts(t, ns1Client, fmt.Sprintf("secret-%v", i), 25)
		})
		wg.Go(func() {
			populateAuth(t, ns1Client, fmt.Sprintf("userpass-%v", i), 25)
		})
	}

	wg.Wait()

	_, err = client.Logical().Delete("sys/namespaces/ns1")
	require.NoError(t, err)

	// This should effectively cancel namespace deletion.
	err = client.Sys().StepDown()
	require.NoError(t, err)

	vault.TestWaitActive(t, cores[1].Core)

	client = cores[1].Client

	resp, err := client.Logical().List("sys/namespaces")
	require.NoError(t, err)
	require.Contains(t, resp.Data, "keys")
	require.Contains(t, resp.Data["keys"], "ns1/")

	resp, err = client.Logical().Read("sys/namespaces/ns1")
	require.NoError(t, err)
	require.Contains(t, resp.Data, "tainted")
	require.True(t, resp.Data["tainted"].(bool))

	_, err = client.Logical().Delete("sys/namespaces/ns1")
	require.NoError(t, err)

	// Ensure namespace eventually is removed.
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		resp, err := client.Logical().List("sys/namespaces")
		require.NoError(t, err)

		if resp == nil {
			return
		}

		if _, ok := resp.Data["keys"]; !ok {
			return
		}

		require.Empty(t, resp.Data["keys"], "did not expect any namespaces")
	}, 10*time.Second, 10*time.Millisecond)

	// Namespace storage should be empty.
	resp, err = client.Logical().List(fmt.Sprintf("sys/raw/namespaces/%v", nsId))
	require.NoError(t, err)
	require.Nil(t, resp)
}

func populateAuth(t *testing.T, client *api.Client, name string, users int) {
	err := client.Sys().EnableAuth(name, "userpass", name)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range users {
		wg.Go(func() {
			_, err := client.Logical().Write(fmt.Sprintf("auth/%v/users/admin-%v", name, i), map[string]any{
				"password":       fmt.Sprintf("secret-%v", i),
				"token_policies": "admin",
			})
			require.NoError(t, err)

			_, err = client.Logical().Write(fmt.Sprintf("auth/%v/login/admin-%v", name, i), map[string]any{
				"password": fmt.Sprintf("secret-%v", i),
			})
			require.NoError(t, err)
		})
	}

	wg.Wait()
}

func populateMounts(t *testing.T, client *api.Client, name string, entries int) {
	err := client.Sys().Mount(name, &api.MountInput{
		Type: "kv-v2",
	})
	require.NoError(t, err)

	// Wait for KVv2 migration to complete.
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		resp, err := client.Logical().Read(fmt.Sprintf("%v/config", name))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.Data, "cas_required")
	}, 10*time.Second, 10*time.Millisecond)

	var wg sync.WaitGroup
	for i := range entries {
		wg.Go(func() {
			_, err := client.KVv2(name).Put(t.Context(), fmt.Sprintf("entry-%v", i), map[string]any{
				"value": i,
			})
			require.NoError(t, err)
		})
	}
	wg.Wait()
}

const adminPolicy = `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "scan", "sudo"]
}
`
