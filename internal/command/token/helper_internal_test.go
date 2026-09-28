// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCommand re-uses the existing Test function to ensure proper behavior of
// the internal token helper
func TestCommand(t *testing.T) {
	helper, err := NewInternalTokenHelper()
	require.NoError(t, err)
	Test(t, helper)
}

func TestInternalHelperFilePerms(t *testing.T) {
	tmpDir := t.TempDir()

	helper, err := NewInternalTokenHelper()
	require.NoError(t, err)
	helper.tokenPath = filepath.Join(tmpDir, ".vault-token")

	f, err := os.Create(helper.tokenPath)
	require.NoError(t, err)
	defer f.Close()

	fi, err := os.Stat(helper.tokenPath)
	require.NoError(t, err)

	if fi.Mode().Perm()&0o04 != 0o04 {
		t.Fatalf("expected world-readable/writable permission bits, got: %o", fi.Mode().Perm())
	}

	err = helper.Store("bogus_token")
	require.NoError(t, err)

	fi, err = os.Stat(helper.tokenPath)
	require.NoError(t, err)

	if fi.Mode().Perm()&0o04 != 0 {
		t.Fatalf("expected no world-readable/writable permission bits, got: %o", fi.Mode().Perm())
	}
}
