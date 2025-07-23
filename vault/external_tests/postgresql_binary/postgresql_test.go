package raft_binary

import (
	"context"
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
}
