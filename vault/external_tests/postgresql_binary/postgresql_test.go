package raft_binary

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/assert"
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
	for range 10 {
		wg.Go(func() {
			var localLogs []string

			// 5 iterations is roughly 2.5 seconds with the 5ms sleep.
			for range 500 {
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
		})
	}

	// Now sacrifice the leader's lock and ensure it doesn't write.
	db, err := psql.Client(t.Context())
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
	index, err := testcluster.WaitForActiveNode(t.Context(), cluster)
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

func TestPostgreSQL_ParallelInit(t *testing.T) {
	t.Parallel()

	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("missing $BAO_BINARY")
	}

	psql := docker.NewPostgreSQLStorage(t, "")
	defer func() { require.NoError(t, psql.Cleanup()) }()

	opts := &docker.DockerClusterOptions{
		ImageRepo:   "quay.io/openbao/openbao",
		ImageTag:    "latest",
		VaultBinary: binary,
		CopyFromTo: map[string]string{
			"../../../command/server/test-fixtures/self-init.hcl":   "/openbao/config/self-init.hcl",
			"../../../command/server/test-fixtures/static-seal.hcl": "/openbao/config/static-seal.hcl",
		},
		Storage: psql,
		ClusterOptions: testcluster.ClusterOptions{
			SkipInit: true,
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	nodes := cluster.Nodes()
	client := nodes[0].APIClient()

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		status, err := client.Sys().SealStatus()
		require.NoError(t, err)
		require.True(t, status.Initialized)
		require.False(t, status.Sealed)
	}, time.Minute, 100*time.Millisecond)

	creds := map[string]any{"password": "password"}
	secret, err := client.Logical().Write("auth/userpass/login/admin", creds)

	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotNil(t, secret.Auth)
	cluster.SetRootToken(secret.Auth.ClientToken)

	var active, sealed int
	for i, node := range nodes {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err := node.APIClient().Sys().ListPoliciesWithContext(ctx)
		switch {
		case err == nil:
			active++
			t.Logf("node %d: ACTIVE", i)
		case strings.Contains(err.Error(), consts.ErrSealed.Error()):
			sealed++
			t.Logf("node %d: SEALED", i)
		default:
			t.Logf("node %d: ERROR: %s", i, err)
		}
	}

	t.Logf("State: total=%d active=%d sealed=%d", len(nodes), active, sealed)
	require.Equal(t, len(nodes), active, "all nodes active")
}

func TestPostgreSQL_FatalInit(t *testing.T) {
	t.Parallel()

	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("missing $BAO_BINARY")
	}

	psql := docker.NewPostgreSQLStorage(t, "")
	defer func() {
		require.NoError(t, psql.Cleanup())
	}()

	opts := &docker.DockerClusterOptions{
		ImageRepo:   "quay.io/openbao/openbao",
		ImageTag:    "latest",
		VaultBinary: binary,
		CopyFromTo: map[string]string{
			"../../../command/server/test-fixtures/self-init.hcl":         "/openbao/config/self-init.hcl",
			"../../../command/server/test-fixtures/self-init-failure.hcl": "/openbao/config/self-init-failure.hcl",
			"../../../command/server/test-fixtures/static-seal.hcl":       "/openbao/config/static-seal.hcl",
		},
		Storage: psql,
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 1,
			SkipInit: true,
			// Set these manually since we don't use NewTestDockerCluster(), but
			// NewDockerCluster directly.
			ClusterName: strings.ReplaceAll(t.Name(), "/", "-"),
			Logger:      logging.NewVaultLogger(log.Trace).Named(t.Name()),
		},
	}

	cluster, err := docker.NewDockerCluster(t.Context(), opts)

	// Don't forget to clean up just in case the assertion below fails and the
	// test cluster didn't fail as expected.
	defer func() {
		if err == nil {
			cluster.Cleanup()
		}
	}()

	require.Error(t, err, "node should fail with bad self-init config")

	// Remove the bad config:
	opts.CopyFromTo = map[string]string{
		"../../../command/server/test-fixtures/self-init.hcl":   "/openbao/config/self-init.hcl",
		"../../../command/server/test-fixtures/static-seal.hcl": "/openbao/config/static-seal.hcl",
	}

	cluster, err = docker.NewDockerCluster(t.Context(), opts)
	require.Error(t, err, "node should continue to refuse startup")
}

func TestPostgreSQL_Upgrade(t *testing.T) {
	t.Parallel()

	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("missing $BAO_BINARY")
	}

	psql := docker.NewPostgreSQLStorage(t, "")
	defer func() { require.NoError(t, psql.Cleanup()) }()

	// We do not set binary here as we want to use the last published image.
	opts := &docker.DockerClusterOptions{
		ImageRepo: "quay.io/openbao/openbao",
		ImageTag:  "latest",
		Storage:   psql,
		ClusterOptions: testcluster.ClusterOptions{
			ClusterName: "psql-upgrade",
			NumCores:    3,
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	nodes := cluster.Nodes()
	client := nodes[0].APIClient()

	t.Logf("token: %v vs %v", client.Token(), cluster.GetRootToken())

	// Create some data to test persistence.
	err := client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	require.NoError(t, err, "failed to mount kv")

	_, err = client.KVv2("kv").Put(t.Context(), "a/key", map[string]interface{}{
		"value": "known-value",
	})
	require.NoError(t, err, "failed writing k/v key")

	// Now upgrade the nodes one at a time.
	opts.VaultBinary = binary
	for index, node := range cluster.ClusterNodes {
		func() {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			err = node.Upgrade(ctx, opts)
			require.NoError(t, err, "failed upgrading node %v", index)
		}()
	}

	// Find active leader.
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	activeIdx, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err)

	client = nodes[activeIdx].APIClient()

	// Ensure we can read the secret.
	value, err := client.KVv2("kv").Get(t.Context(), "a/key")
	require.NoError(t, err, "failed reading k/v key")
	require.Equal(t, value.Data["value"], "known-value")
}
