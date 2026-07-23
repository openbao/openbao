// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestPollTLSCertificateChanges(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(cert, []byte("cert-v1"), 0o600))
	require.NoError(t, os.WriteFile(key, []byte("key-v1"), 0o600))

	reloaded := make(chan struct{}, 10)
	stopCh := make(chan struct{})
	defer close(stopCh)

	go pollTLSCertificateChanges([]string{cert, key}, 10*time.Millisecond, func() error {
		reloaded <- struct{}{}
		return nil
	}, stopCh, hclog.NewNullLogger())

	// Unchanged files must not trigger a reload.
	select {
	case <-reloaded:
		t.Fatal("reload triggered without file change")
	case <-time.After(100 * time.Millisecond):
	}

	// A content change must trigger exactly one reload.
	tmp := filepath.Join(dir, "tls.crt.tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("cert-v2"), 0o600))
	require.NoError(t, os.Rename(tmp, cert))
	select {
	case <-reloaded:
	case <-time.After(2 * time.Second):
		t.Fatal("reload not triggered after file change")
	}
	select {
	case <-reloaded:
		t.Fatal("reload triggered twice for a single change")
	case <-time.After(100 * time.Millisecond):
	}
}
