// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
)

func GetRaft(t testing.TB, bootstrap bool, noStoreState bool) (*RaftBackend, string) {
	raftDir := t.TempDir()
	t.Logf("raft dir: %s", raftDir)

	return getRaftWithDir(t, bootstrap, noStoreState, raftDir), raftDir
}

func getRaftWithDir(t testing.TB, bootstrap bool, noStoreState bool, raftDir string) *RaftBackend {
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}
	backend := backendRaw.(*RaftBackend)

	if bootstrap {
		err = backend.Bootstrap([]Peer{
			{
				ID:      backend.NodeID(),
				Address: backend.NodeID(),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		err = backend.SetupCluster(context.Background(), SetupOpts{})
		if err != nil {
			t.Fatal(err)
		}

		for backend.raft.AppliedIndex() < 2 {
		}

	}

	backend.DisableAutopilot()

	return backend
}
