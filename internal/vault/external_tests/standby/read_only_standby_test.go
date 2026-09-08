// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package standby_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	logicalKv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	logicalPki "github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadOnlyStandby(t *testing.T) {
	const (
		timeout = 10 * time.Second
		tick    = 100 * time.Millisecond
	)

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
	t.Cleanup(cluster.Cleanup)

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
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			_, err := core.Client.KVv2("kv").Put(t.Context(), "foo", map[string]any{
				"bar": expectedValue,
			})
			require.NoError(collect, err)
		}, timeout, tick)

		t.Logf("validating expected value on primary %d", i)
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			data, err := primaryClient.KVv2("kv").Get(t.Context(), "foo")
			require.NoError(collect, err)
			require.Equal(collect, expectedValue, data.Data["bar"])
		}, timeout, tick)

		t.Logf("validating expected value on standby %d", i)
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			data, err := standbyClient.KVv2("kv").Get(t.Context(), "foo")
			require.NoError(collect, err)
			require.Equal(collect, expectedValue, data.Data["bar"])
		}, timeout, tick)
	}

	t.Log("revoking token")
	errRevoke := primaryClient.Auth().Token().RevokeTreeWithContext(t.Context(), token.Auth.ClientToken)
	require.NoError(t, errRevoke)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err = standbyClient.KVv2("kv").Get(t.Context(), "foo")
		require.ErrorContains(collect, err, "permission denied", "token was revoked on the primary, should be declined by secondaries")
	}, timeout, tick)
}

func TestReadOnlyStandbysForwardingWrapping(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv-v2": vault.PassthroughBackendFactory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	leader := cores[0].Core
	vault.TestWaitActive(t, leader)
	client := cores[0].Client
	client.SetToken(cluster.RootToken)

	require.NoError(t, client.Sys().Mount("wraptest", &api.MountInput{Type: "kv-v2"}))

	req := &logical.Request{
		Path:        "wraptest/secret",
		ClientToken: cluster.RootToken,
		Operation:   logical.CreateOperation,
		Data: map[string]any{
			"foo": "bar",
		},
	}

	resp, err := leader.HandleRequest(namespace.RootContext(t.Context()), req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Standby nodes also handle the wrapping request (standby by forwarding)
	for _, core := range cores {
		req = &logical.Request{
			Path:        "wraptest/secret",
			ClientToken: cluster.RootToken,
			Operation:   logical.ReadOperation,
			WrapInfo: &logical.RequestWrapInfo{
				TTL: time.Duration(15 * time.Second),
			},
		}

		resp, err = core.HandleRequest(namespace.RootContext(t.Context()), req)
		if core.HAState() == consts.Active {
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, time.Duration(15*time.Second), resp.WrapInfo.TTL)
		} else {
			require.Error(t, err)
			require.True(t, logical.ShouldForward(err))
		}
	}
}
