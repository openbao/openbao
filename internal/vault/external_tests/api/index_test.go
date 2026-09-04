// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
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

	mgr := api.NewSimpleIndexManager()
	active := cluster.Cores[0].Client.WithIndexManager(mgr)

	// Set up a secrets engine.
	err := active.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v1",
	})
	require.NoError(t, err)

	// Get a client that sends request to a standby.
	standbyClient := func() *api.Client {
		standbys := testhelpers.DeriveStandbyCores(t, cluster)
		require.NotEmpty(t, standbys, "expected at least one standby core")
		client := standbys[0].Client
		client.SetMaxRetries(2)
		return client
	}

	// Send a write, check the index.
	standby := standbyClient().WithIndexManager(mgr)

	err = standby.KVv1("kv").Put(t.Context(), "testing", map[string]any{
		"data": "testing",
	})
	require.NoError(t, err)

	firstIdx := mgr.Get(standby.Address(), "")
	require.NotEmpty(t, firstIdx)

	// Send a second write, ensure it is greater.
	err = standby.KVv1("kv").Put(t.Context(), "testing", map[string]any{
		"data": "testing-2",
	})
	require.NoError(t, err)

	secondIdx := mgr.Get(standby.Address(), "")
	require.NotEmpty(t, secondIdx)

	firstDecoded, err := api.DecodeIndexValue(firstIdx)
	require.NoError(t, err, "index: %v", firstIdx)
	require.NotNil(t, firstDecoded)
	firstIndex := firstDecoded.Value

	secondDecoded, err := api.DecodeIndexValue(secondIdx)
	require.NoError(t, err, "index: %v", secondIdx)
	require.NotNil(t, secondDecoded)
	secondIndex := secondDecoded.Value

	firstIdxInt, err := parseutil.ParseInt(firstIndex)
	require.NoError(t, err)
	secondIdxInt, err := parseutil.ParseInt(secondIndex)
	require.NoError(t, err)
	require.Greater(t, secondIdxInt, firstIdxInt)

	active.SetIndexManager(mgr)

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
		standby.SetInconsistent(behavior)
		var wg sync.WaitGroup
		for count := range 20 {
			// Each client will be internally consistent this way.
			wg.Go(func() {
				var lastIndex string
				mgr := api.NewSimpleIndexManager()
				ac := active.WithIndexManager(mgr)
				sc := standby.WithIndexManager(mgr)

				for item := range 5 {
					entry := fmt.Sprintf("testing-%v", count)
					expected := fmt.Sprintf("%v-%v", count, item)
					err := ac.KVv1("kv").Put(t.Context(), entry, map[string]any{
						"count": count,
						"item":  item,
						"value": expected,
					})
					require.NoError(t, err)
					thisIndex := mgr.Get(sc.Address(), "")

					resp, err := sc.KVv1("kv").Get(t.Context(), entry)
					require.NoError(t, err)
					require.NotEmpty(t, resp)
					require.Contains(t, resp.Data, "value")
					actual := resp.Data["value"].(string)

					followupIndex := mgr.Get(sc.Address(), "")
					require.Equal(t, expected, actual, "failed:\n\twith behavior: %v\n\tfrom write index: %v\n\twith subsequent index: %v\n\tlast index: %v\n\tresp: %v", behavior, thisIndex, followupIndex, lastIndex, resp)
					lastIndex = thisIndex
				}
			})
		}

		wg.Wait()
	}

	// Disable retries; validate fail vs forward logic.
	standby.SetMaxRetries(0)

	// Adding ones to the end should result in the request failing for fail
	// mode.
	thisIndex := mgr.Get(standby.Address(), "")
	decoded, err := api.DecodeIndexValue(thisIndex)
	require.NoError(t, err)
	decoded.Value += "11"
	thisIndex, err = decoded.Encode()
	require.NoError(t, err)
	mgr.Set(standby.Address(), thisIndex)

	standby.FailInconsistent()
	resp, err := standby.KVv1("kv").Get(t.Context(), "testing")
	require.ErrorContains(t, err, "429")
	require.Nil(t, resp)

	// Setting the mode to forward should result in a valid response.
	thisIndex = mgr.Get(standby.Address(), "")
	decoded, err = api.DecodeIndexValue(thisIndex)
	require.NoError(t, err)
	decoded.Value += "11"
	thisIndex, err = decoded.Encode()
	require.NoError(t, err)
	mgr.Set(standby.Address(), thisIndex)

	standby.ForwardInconsistent()
	resp, err = standby.KVv1("kv").Get(t.Context(), "testing")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "data")
	require.Equal(t, "testing-2", resp.Data["data"])
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

	mgr := api.NewSimpleIndexManager()
	active := cluster.Cores[0].Client.WithIndexManager(mgr)

	// Set up a secrets engine.
	err := active.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v1",
	})
	require.NoError(t, err)

	// Send a write, check the index.
	standby := cluster.Cores[1].Client.WithIndexManager(mgr)
	standby.AwaitInconsistent(api.IndexInconsistentFail)

	err = standby.KVv1("kv").Put(t.Context(), "testing", map[string]any{
		"data": "testing",
	})
	require.NoError(t, err)

	// Now set up read/writes to the active and standby, but make the client
	// pretend it doesn't understand index headers. Ensure we don't ever see
	// a stale read.

	standby.SetInconsistent(nil)
	standby.SetIndexManager(nil)

	var wg sync.WaitGroup
	for count := range 20 {
		wg.Go(func() {
			var lastIndex string
			for item := range 5 {
				entry := fmt.Sprintf("testing-%v", count)
				expected := fmt.Sprintf("%v-%v", count, item)
				err := active.KVv1("kv").Put(t.Context(), entry, map[string]any{
					"count": count,
					"item":  item,
					"value": expected,
				})
				require.NoError(t, err)
				thisIndex := mgr.Get(standby.Address(), "")

				resp, err := standby.KVv1("kv").Get(t.Context(), entry)
				require.NoError(t, err)
				require.NotEmpty(t, resp)
				require.Contains(t, resp.Data, "value")
				actual := resp.Data["value"].(string)

				followupIndex := mgr.Get(standby.Address(), "")
				require.Equal(t, expected, actual, "failed:\n\tfrom write index: %v\n\twith subsequent index: %v\n\tlast index: %v\n\tresp: %v", thisIndex, followupIndex, lastIndex, resp)
				lastIndex = thisIndex
			}
		})
	}

	wg.Wait()

	// Because we set a really long await period, we should be able to park
	// this request for 5 seconds and watch it fail due to context
	// cancellation.

	standby.AwaitInconsistent(api.IndexInconsistentFail)
	standby.SetIndexManager(mgr)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	thisIndex := mgr.Get(standby.Address(), "")
	decoded, err := api.DecodeIndexValue(thisIndex)
	require.NoError(t, err)
	decoded.Value += "11"
	thisIndex, err = decoded.Encode()
	require.NoError(t, err)
	mgr.Set(standby.Address(), thisIndex)

	resp, err := standby.KVv1("kv").Get(ctx, "testing")
	require.Error(t, err)
	require.Nil(t, resp)
	require.Error(t, ctx.Err())
}
