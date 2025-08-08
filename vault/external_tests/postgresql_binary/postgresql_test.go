package raft_binary

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func TestPostgreSQL_FencedWrites(t *testing.T) {
	t.Parallel()
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $VAULT_BINARY present")
	}

	psql := docker.NewPostgreSQLStorage(t, "")
	opts := &docker.DockerClusterOptions{
		ImageRepo: "quay.io/openbao/openbao",
		// We're replacing the binary anyway, so we're not too particular about
		// the docker image version tag.
		ImageTag:    "latest",
		NetworkName: "",
		VaultBinary: binary,
		ClusterOptions: testcluster.ClusterOptions{
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
			},
		},
		Storage: psql,
	}
	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	// Ensure the cluster has come up alright.
	client := cluster.Nodes()[0].APIClient()
	resp, err := client.Logical().List("sys/policies/acl")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Now sacrifice the leader's lock and ensure it doesn't write.
	db, err := psql.Client(context.Background())
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM openbao_ha_locks")
	require.NoError(t, err)
	t.Logf("removed all locks")

	// This should now fail since the fenced write will fail.
	resp, err = client.Logical().Write("sys/policies/acl/custom", map[string]interface{}{
		"policy": `path "*" {
    capabilities = ["sudo"]
}`,
	})
	require.Error(t, err, "response: %v", resp)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), physical.ErrFencedWriteFailed)

	// Give it some time for the leader to detect it is not active.
	time.Sleep(6 * time.Second)

	// If we wait long enough, another node should pick up active leadership.
	index, err := testcluster.WaitForActiveNode(context.Background(), cluster)
	require.NoError(t, err)
	t.Logf("detected node %v was active", index)
	client = cluster.Nodes()[index].APIClient()

	// Retrying the write should succeed.
	resp, err = client.Logical().Write("sys/policies/acl/custom", map[string]interface{}{
		"policy": `path "*" {
    capabilities = ["sudo"]
}`,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

type nodeResult struct {
	cluster *docker.DockerCluster
	err     error
}

func TestPSQLParallelInit(t *testing.T) {
	t.Parallel()

	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("missing $BAO_BINARY")
	}

	configPath := "config-postgresql.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("config not found: %s", configPath)
	}

	psql := docker.NewPostgreSQLStorage(t, "")
	defer psql.Cleanup()

	const numNodes = 10
	targetTime := time.Now().Add(2 * time.Second)

	results := make(chan nodeResult, numNodes)
	for i := 0; i < numNodes; i++ {
		go func(idx int) {
			// sync start
			if d := time.Until(targetTime); d > 0 {
				time.Sleep(d)
			}
			// prepare config
			data, err := os.ReadFile(configPath)
			require.NoError(t, err)
			var cfg map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &cfg))
			if st, ok := cfg["storage"].(map[string]interface{}); ok {
				if pg, ok := st["postgresql"].(map[string]interface{}); ok {
					pg["connection_url"] = psql.InternalUrl
					pg["ha_enabled"] = true
				}
			}
			cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
			tmp, _ := os.CreateTemp("", fmt.Sprintf("cfg-%02d-*.json", idx))
			tmp.Write(cfgBytes)
			tmp.Close()
			defer os.Remove(tmp.Name())

			// start node
			opts := &docker.DockerClusterOptions{
				ImageRepo:   "quay.io/openbao/openbao",
				ImageTag:    "latest",
				VaultBinary: binary,
				Args:        []string{"server", "-config", tmp.Name()},
				Storage:     psql,
				ClusterOptions: testcluster.ClusterOptions{
					VaultNodeConfig: &testcluster.VaultNodeConfig{LogLevel: "TRACE"},
					NumCores:        1,
				},
			}
			cluster := docker.NewTestDockerCluster(t, opts)

			// basic operation
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err = cluster.Nodes()[0].APIClient().
				Logical().ListWithContext(ctx, "sys/policies/acl")

			results <- nodeResult{cluster: cluster, err: err}
		}(i)
	}

	// collect results
	var active, sealed int
	for i := 0; i < numNodes; i++ {
		res := <-results
		if res.err == nil {
			active++
		} else if strings.Contains(res.err.Error(), "Vault is sealed") {
			sealed++
		} else {
			t.Errorf("unexpected node error: %v", res.err)
		}
		defer res.cluster.Cleanup()
	}

	t.Logf("active=%d sealed=%d", active, sealed)
	require.Greater(t, active, 0, "need at least one active leader")
	require.Equal(t, numNodes-1, sealed, "rest should be sealed standby")
}
