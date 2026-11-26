// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

func GetRaft(t testing.TB, bootstrap bool, noStoreState bool) *RaftBackend {
	raftDir := t.TempDir()
	t.Logf("raft dir: %s", raftDir)

	return getRaftWithDir(t, bootstrap, noStoreState, raftDir)
}

func getRaftWithDir(t testing.TB, bootstrap bool, noStoreState bool, raftDir string) *RaftBackend {
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  fmt.Sprintf("raft-%s", id),
		Level: hclog.Trace,
	})
	logger.Info("raft dir", "dir", raftDir)

	conf := map[string]string{
		"path":          raftDir,
		"trailing_logs": "100",
		"node_id":       id,
	}

	if noStoreState {
		conf["doNotStoreLatestState"] = ""
	}

	backendRaw, err := NewRaftBackend(conf, logger)
	require.NoError(t, err)
	backend := backendRaw.(*RaftBackend)

	if bootstrap {
		err = backend.Bootstrap([]Peer{
			{
				ID:      backend.NodeID(),
				Address: backend.NodeID(),
			},
		})
		require.NoError(t, err)

		err = backend.SetupCluster(context.Background(), SetupOpts{})
		require.NoError(t, err)

		for backend.raft.AppliedIndex() < 2 {
		}

	}

	backend.DisableAutopilot()

	return backend
}
