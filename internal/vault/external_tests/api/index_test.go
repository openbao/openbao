// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestHTTP_Index_Defaults(t *testing.T) {
	cfg := &vault.CoreConfig{}

	opts := &vault.TestClusterOptions{
		HandlerFunc:              vaulthttp.Handler,
		DefaultHandlerProperties: vault.HandlerProperties{
			// ListenerConfig: &configutil.Listener{},
		},
		NumCores: 2,
	}
	teststorage.RaftBackendSetup(cfg, opts)

	cluster := vault.NewTestCluster(t, cfg, opts)
	cluster.Start()
	defer cluster.Cleanup()

	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	// Cloning a client doesn't let you change the config; we have to create
	// a whole new client.
	//
	// TODO: fix after adding an external interface
	activeCfg := cluster.Cores[0].Client.CloneConfig()
	activeCfg.DefaultStrongConsistency = true
	activeCfg.CloneToken = true
	active, err := api.NewClient(activeCfg)
	require.NoError(t, err)
	active.SetToken(cluster.Cores[0].Client.Token())

	// Set up a secrets engine.
	err = active.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v1",
	})
	require.NoError(t, err)

	// Get a client that sends request to a standby.
	standbyClient := func() *api.Client {
		standbys := testhelpers.DeriveStandbyCores(t, cluster)
		require.NotEmpty(t, standbys, "expected at least one standby core")
		cfg := standbys[0].Client.CloneConfig()
		cfg.DefaultStrongConsistency = true
		cfg.CloneToken = true
		client, err := api.NewClient(cfg)
		require.NoError(t, err)
		client.SetMaxRetries(2)
		client.SetToken(standbys[0].Client.Token())
		return client
	}

	// Send a write, check the index.
	//
	// TODO: convert to stable external API once it exists.
	standby := standbyClient()

	request := standby.NewRequest(http.MethodPut, "/v1/kv/testing")
	request.BodyBytes = []byte(`{"data":"testing"}`)
	resp, err := standby.RawRequest(request)
	require.NoError(t, err)
	require.NotNil(t, resp)
	index := resp.Header.Get(api.IndexHeaderName)
	require.NotEmpty(t, index)
	firstIndex, err := api.DecodeIndexValue(index)
	require.NoError(t, err)

	// Send a second write, ensure it is a different index value.

	request = standby.NewRequest(http.MethodPut, "/v1/kv/testing")
	request.BodyBytes = []byte(`{"data":"testing-2"}`)
	resp, err = standby.RawRequest(request)
	require.NoError(t, err)
	require.NotNil(t, resp)
	index = resp.Header.Get(api.IndexHeaderName)
	require.NotEmpty(t, index)
	secondIndex, err := api.DecodeIndexValue(index)
	require.NoError(t, err)

	require.NotEqual(t, firstIndex.Value, secondIndex.Value)
	require.NotEmpty(t, firstIndex.Value)
	require.NotEmpty(t, secondIndex.Value)

	// We should always be able to write to the primary and see the write on
	// the standby because we share an index manager. This should hold
	// regardless of standby behavior.
	behaviors := [][]string{
		nil,
		{api.IndexInconsistentFail},
		{api.IndexInconsistentForward},
		{api.IndexInconsistentAwait},
		{api.IndexInconsistentAwait, api.IndexInconsistentFail},
		{api.IndexInconsistentAwait, api.IndexInconsistentForward},
	}
	for _, behavior := range behaviors {
		standby.SetInconsistent(behavior...)
		var wg sync.WaitGroup
		for count := range 20 {
			// Each client will be internally consistent this way.
			wg.Go(func() {
				// Cloning a client preserves the index manager instance. We
				// want a new one that we share across active/standby.
				ac, err := api.NewClient(activeCfg)
				require.NoError(t, err)
				ac.SetToken(cluster.Cores[0].Client.Token())

				sc, err := ac.Clone()
				require.NoError(t, err)
				require.NoError(t, sc.SetAddress(standby.Address()))

				for item := range 5 {
					entry := fmt.Sprintf("testing-%v", count)
					expected := fmt.Sprintf("%v-%v", count, item)
					err := ac.KVv1("kv").Put(t.Context(), entry, map[string]any{
						"count": count,
						"item":  item,
						"value": expected,
					})
					require.NoError(t, err)

					resp, err := sc.KVv1("kv").Get(t.Context(), entry)
					require.NoError(t, err)
					require.NotEmpty(t, resp)
					require.Contains(t, resp.Data, "value")
					actual := resp.Data["value"].(string)

					require.Equal(t, expected, actual, "failed with behavior: %v", behavior)
				}
			})
		}

		wg.Wait()
	}

	// Use the stock client: this will lack a manager and thus accept index
	// values from the headers.
	//
	// TODO: Fix this test to use index manager properly once an external
	// interface is defined.
	standby = cluster.Cores[1].Client

	// Adding ones to the end should result in the request failing for fail
	// mode.
	secondIndex.Value += "1111"
	futureIndex, err := secondIndex.Encode()
	require.NoError(t, err)

	standby.AddHeader(api.IndexHeaderName, futureIndex)

	standby.SetInconsistent(api.IndexInconsistentFail)
	secret, err := standby.KVv1("kv").Get(t.Context(), "testing")
	require.ErrorContains(t, err, "429")
	require.Nil(t, secret)

	// Setting the mode to forward should result in a valid response.
	standby.SetInconsistent(api.IndexInconsistentForward)
	secret, err = standby.KVv1("kv").Get(t.Context(), "testing")
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.Contains(t, secret.Data, "data")
	require.Equal(t, "testing-2", secret.Data["data"])
}

func TestHTTP_Index_ForwardMissingAndAwait(t *testing.T) {
	t.Parallel()

	cfg := &vault.CoreConfig{}

	opts := &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		DefaultHandlerProperties: vault.HandlerProperties{
			ListenerConfig: &configutil.Listener{
				ConsistencyMissingHeaderForward: true,
				ConsistencyMaxIndexWait:         500 * time.Second,
			},
		},
		NumCores: 2,
	}
	teststorage.RaftBackendSetup(cfg, opts)

	cluster := vault.NewTestCluster(t, cfg, opts)
	cluster.Start()
	defer cluster.Cleanup()

	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	// Cloning a client doesn't let you change the config; we have to create
	// a whole new client.
	//
	// TODO: fix after adding an external interface
	activeCfg := cluster.Cores[0].Client.CloneConfig()
	activeCfg.DefaultStrongConsistency = true
	activeCfg.CloneToken = true
	active, err := api.NewClient(activeCfg)
	require.NoError(t, err)
	active.SetToken(cluster.Cores[0].Client.Token())

	// Set up a secrets engine.
	err = active.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v1",
	})
	require.NoError(t, err)

	standby, err := active.Clone()
	require.NoError(t, err)
	require.NoError(t, standby.SetAddress(cluster.Cores[1].Client.Address()))

	// Send a write, check the index.
	standby.SetInconsistent(api.IndexInconsistentAwait, api.IndexInconsistentFail)
	err = standby.KVv1("kv").Put(t.Context(), "testing", map[string]any{
		"data": "testing",
	})
	require.NoError(t, err)

	// Now set up read/writes to the active and standby, but make the client
	// pretend it doesn't understand index headers. Ensure we don't ever see
	// a stale read.

	var wg sync.WaitGroup
	for count := range 20 {
		wg.Go(func() {
			standby := cluster.Cores[1].Client

			for item := range 5 {
				entry := fmt.Sprintf("testing-%v", count)
				expected := fmt.Sprintf("%v-%v", count, item)
				err := active.KVv1("kv").Put(t.Context(), entry, map[string]any{
					"count": count,
					"item":  item,
					"value": expected,
				})
				require.NoError(t, err)

				resp, err := standby.KVv1("kv").Get(t.Context(), entry)
				require.NoError(t, err)
				require.NotEmpty(t, resp)
				require.Contains(t, resp.Data, "value")
				actual := resp.Data["value"].(string)

				require.Equal(t, expected, actual)
			}
		})
	}

	wg.Wait()

	// Because we set a really long await period, we should be able to park
	// this request for 5 seconds and watch it fail due to context
	// cancellation.
	//
	// TODO: hack until we add a proper external interface

	standby = cluster.Cores[1].Client
	standby.SetInconsistent(api.IndexInconsistentAwait, api.IndexInconsistentFail)

	health, err := active.Sys().Health()
	require.NoError(t, err)
	require.NotEmpty(t, health.ClusterID)

	futureIndex := &api.IndexValue{
		Cluster: health.ClusterID,
		Value:   "111111111111",
	}

	encoded, err := futureIndex.Encode()
	require.NoError(t, err)
	standby.AddHeader(api.IndexHeaderName, encoded)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := standby.KVv1("kv").Get(ctx, "testing")
	require.Error(t, err)
	require.Nil(t, resp)
	require.Error(t, ctx.Err())
}
