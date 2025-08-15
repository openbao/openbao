package raft_binary

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func TestPostgreSQL_FencedWrites(t *testing.T) {
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

	// Spam a couple of goroutines to see if we get a lock failure.
	var foundFailure atomic.Bool
	var logLock sync.Mutex
	var logs []string
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var localLogs []string

			// 5 iterations is roughly 2.5 seconds with the 5ms sleep.
			for j := 0; j < 500; j++ {
				// This should now fail since the fenced write will fail.
				resp, err := client.Logical().Write("sys/policies/acl/custom", map[string]interface{}{
					"policy": `path "*" {
    capabilities = ["sudo"]
}`,
				})

				if resp != nil {
					localLogs = append(localLogs, fmt.Sprintf("resp=%v / err=%v", resp, err))
				} else if err != nil {
					localLogs = append(localLogs, fmt.Sprintf("err=%v", err))
				}

				if err != nil && strings.Contains(err.Error(), physical.ErrFencedWriteFailed) {
					foundFailure.Store(true)
					break
				}

				if foundFailure.Load() {
					break
				}

				time.Sleep(5 * time.Millisecond)
			}

			// Aggregate (unique) logs in case of failure.
			logLock.Lock()
			seenLogs := map[string]struct{}{}
			for _, log := range localLogs {
				if _, seen := seenLogs[log]; seen {
					break
				}

				logs = append(logs, log)
				seenLogs[log] = struct{}{}
			}
			logLock.Unlock()
		}()
	}

	// Now sacrifice the leader's lock and ensure it doesn't write.
	db, err := psql.Client(context.Background())
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM openbao_ha_locks")
	require.NoError(t, err)
	t.Logf("removed all locks")

	wg.Wait()
	if !foundFailure.Load() {
		for _, log := range logs {
			t.Logf("got failure log: %v", log)
		}
		t.Fatalf("expected at least one thread to fail with leadership change error / logs=%v", len(logs))
	}
	t.Logf("got logs: %v", len(logs))

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
	require.Nil(t, resp)
}
