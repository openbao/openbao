package command

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/cli"
	log "github.com/hashicorp/go-hclog"
	testintf "github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

// Waiting on anything but raft would add most of a minute to the first boot of
// every other deployment. Core is nil on purpose: reaching for it here is the
// bug we're guarding against.
func TestWaitForRaftRetryJoinSkipsNonRaft(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		storage *server.Storage
	}{
		{name: "file_storage", storage: &server.Storage{Type: "file"}},
		{name: "inmem_storage", storage: &server.Storage{Type: "inmem"}},
		{name: "raft_ha_storage_only", storage: &server.Storage{Type: "postgresql"}},
		{name: "no_storage", storage: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cmd := &ServerCommand{logger: log.NewInterceptLogger(&log.LoggerOptions{Output: io.Discard})}

			start := time.Now()
			joined, err := cmd.waitForRaftRetryJoin(context.Background(), nil, &server.Config{Storage: tc.storage})

			require.NoError(t, err)
			require.False(t, joined, "reported a join we never waited for")
			require.Less(t, time.Since(start), time.Second,
				"we waited, so the wait is being applied to non-raft storage")
		})
	}
}

// testRaftCore brings up a single-node raft-backed cluster, optionally with a
// retry_join stanza, and hands back a command and its core.
func testRaftCore(t *testing.T, retryJoin string) (*ServerCommand, *vault.Core, func()) {
	t.Helper()

	testSeal, _ := seal.NewTestSeal(nil)
	autoSeal, err := vault.NewAutoSeal(testSeal)
	require.NoError(t, err)

	logger := log.NewInterceptLogger(&log.LoggerOptions{Output: io.Discard})
	conf, opts := teststorage.ClusterSetup(&vault.CoreConfig{
		Logger: logger,
		Seal:   autoSeal,
	}, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		Logger:      logger,
		NumCores:    1,
	}, func(_ *vault.CoreConfig, opts *vault.TestClusterOptions) {
		opts.PhysicalFactory = func(t testintf.T, coreIdx int, logger log.Logger, _ map[string]any) *vault.PhysicalBackendBundle {
			extra := map[string]any{}
			if retryJoin != "" {
				extra["retry_join"] = retryJoin
			}
			return teststorage.MakeRaftBackend(t, coreIdx, logger, extra)
		}
	})

	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()

	cmd := &ServerCommand{
		BaseCommand: &BaseCommand{UI: cli.NewMockUi()},
		ShutdownCh:  MakeShutdownCh(),
		SighupCh:    MakeSighupCh(),
		SigUSR2Ch:   MakeSigUSR2Ch(),
		logger:      logger,
	}

	return cmd, cluster.Cores[0].Core, cluster.Cleanup
}

func testRaftConfig() *server.Config {
	return &server.Config{Storage: &server.Storage{Type: storageTypeRaft}}
}

// Raft on its own isn't enough: with no retry_join stanza there is no join
// coming, so we mustn't hold up initialization waiting for one.
func TestWaitForRaftRetryJoinWithoutJoinConfig(t *testing.T) {
	cmd, core, cleanup := testRaftCore(t, "")
	defer cleanup()

	start := time.Now()
	joined, err := cmd.waitForRaftRetryJoin(context.Background(), core, testRaftConfig())

	require.NoError(t, err)
	require.False(t, joined)
	require.Less(t, time.Since(start), time.Second, "waited despite there being no retry_join")
}

// An initialized core is the state a follower reaches once its join lands, and
// the one case we must not self-initialize over.
func TestWaitForRaftRetryJoinAlreadyInitialized(t *testing.T) {
	cmd, core, cleanup := testRaftCore(t, `[{"leader_api_addr":"https://127.0.0.1:8200"}]`)
	defer cleanup()

	start := time.Now()
	joined, err := cmd.waitForRaftRetryJoin(context.Background(), core, testRaftConfig())

	require.NoError(t, err)
	require.True(t, joined, "an initialized node should count as joined")
	require.Less(t, time.Since(start), time.Second, "waited despite the node already being up")
}
