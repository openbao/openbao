// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A standby answers the snapshot paths with a redirect; the client does not
// follow it, so the caller has to be told what to do about it.
func TestRaftSnapshotRestoreRedirectNamesTheActiveNode(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/storage/raft/snapshot" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Location", "https://active.example.com:8200/v1/sys/storage/raft/snapshot")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer mock.Close()

	cfg := DefaultConfig()
	cfg.Address = mock.URL
	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Sys().RaftSnapshotRestore(strings.NewReader("snapshot"), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "active node")
	require.Contains(t, err.Error(), "https://active.example.com:8200/v1/sys/storage/raft/snapshot")
}

func TestRaftSnapshotRestoreAcceptsNoContent(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer mock.Close()

	cfg := DefaultConfig()
	cfg.Address = mock.URL
	client, err := NewClient(cfg)
	require.NoError(t, err)

	require.NoError(t, client.Sys().RaftSnapshotRestore(strings.NewReader("snapshot"), true))
}
