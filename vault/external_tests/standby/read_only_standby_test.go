// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package standby_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	logicalPki "github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/helper/testhelpers"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"

	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadOnlyStandby(t *testing.T) {
	conf := vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": logicalPki.Factory,
			"kv":  logicalKv.VersionedKVFactory,
		},
	}
	opts := vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	}

	teststorage.RaftBackendSetup(&conf, &opts)
	cluster := vault.NewTestCluster(t, &conf, &opts)

	cluster.Start()
	defer cluster.Cleanup()

	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)
	require.False(t, cluster.Cores[0].Standby())

	primaryClient := cluster.Cores[0].Client
	standbyClient := cluster.Cores[1].Client

	require.NoError(t, primaryClient.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v2",
	}))

	token, err := primaryClient.Auth().Token().CreateWithContext(t.Context(), &api.TokenCreateRequest{})
	require.NoError(t, err)
	standbyClient.SetToken(token.Auth.ClientToken)

	for i, core := range cluster.Cores {
		expectedValue := fmt.Sprintf("expected value #%d", i)

		t.Logf("writing expected value on node %d", i)
		_, err := core.Client.KVv2("kv").Put(t.Context(), "foo", map[string]any{
			"bar": expectedValue,
		})
		require.NoError(t, err)

		t.Logf("validating expected value on primary %d", i)
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			data, err := primaryClient.KVv2("kv").Get(t.Context(), "foo")
			require.NoError(collect, err)
			require.Equal(collect, expectedValue, data.Data["bar"])
		}, 10*time.Second, 100*time.Millisecond)

		t.Logf("validating expected value on standby %d", i)
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			data, err := standbyClient.KVv2("kv").Get(t.Context(), "foo")
			require.NoError(collect, err)
			require.Equal(collect, expectedValue, data.Data["bar"])
		}, 10*time.Second, 100*time.Millisecond)
	}

	t.Log("revoking token")
	require.NoError(t, primaryClient.Auth().Token().RevokeTreeWithContext(t.Context(), token.Auth.ClientToken))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err = standbyClient.KVv2("kv").Get(t.Context(), "foo")
		require.ErrorContains(collect, err, "permission denied", "token was revoked on the primary, should be declined by secondaries")
	}, 10*time.Second, 100*time.Millisecond)
}
