// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestSysLeader_get(t *testing.T) {
	requestSysLeader := func(t *testing.T, client *http.Client, addr string) map[string]any {
		t.Helper()

		resp, err := client.Get(addr + "/v1/sys/leader")
		require.NoError(t, err)

		var actual map[string]any

		testResponseStatus(t, resp, 200)
		testResponseBody(t, resp, &actual)

		return actual
	}

	t.Run("non-ha", func(t *testing.T) {
		core, _, _ := vault.TestCoreUnsealed(t)
		ln, addr := TestServer(t, core)
		defer func() {
			require.NoError(t, ln.Close())
		}()

		actual := requestSysLeader(t, http.DefaultClient, addr)
		require.Equal(t, map[string]any{
			"ha_enabled": false,
		}, actual)
	})

	t.Run("ha", func(t *testing.T) {
		testStartTime := time.Now()
		cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
			NumCores:    2,
			HandlerFunc: Handler,
		})
		testhelpers.WaitForActiveNodeAndStandbys(t, cluster)
		t.Cleanup(cluster.Cleanup)

		// primary
		actual := requestSysLeader(t, &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   cluster.Nodes()[0].TLSConfig(),
				ForceAttemptHTTP2: true,
			},
		}, cluster.Cores[0].Client.Address())

		require.Contains(t, actual, "active_time")
		activeTime, err := time.Parse(time.RFC3339, actual["active_time"].(string))
		require.NoError(t, err)
		require.WithinRange(t, activeTime, testStartTime, time.Now())
		delete(actual, "active_time")

		expected := map[string]any{
			"ha_enabled":             true,
			"is_self":                true,
			"leader_address":         cluster.Cores[0].Client.Address(),
			"leader_cluster_address": cluster.Cores[0].ClusterAddr(),
			// "active_time" is tested above and removed from the map
		}
		require.Equal(t, expected, actual)

		// standby
		expected["is_self"] = false

		actual = requestSysLeader(t, &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   cluster.Nodes()[1].TLSConfig(),
				ForceAttemptHTTP2: true,
			},
		}, cluster.Cores[1].Client.Address())

		require.Equal(t, expected, actual)
	})
}
