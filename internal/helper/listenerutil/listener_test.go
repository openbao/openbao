// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"crypto/tls"
	"math"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurveIDsMatchGoStdLib(t *testing.T) {
	for i := range math.MaxUint16 + 1 {
		id := tls.CurveID(i)
		name := id.String()

		supportedCurveID := !strings.HasPrefix(name, "CurveID(")

		got, ok := curveIDByName[name]
		switch {
		// Tripwire in case new Go versions add more CurveIDs we need to support
		case supportedCurveID && !ok:
			t.Errorf("missing mapping in CurveToCurveID, please add new %s (0x%04x)", name, i)
		case supportedCurveID && got != id:
			t.Errorf("CurveToCurveID(%q) = 0x%04x, want 0x%04x", name, got, id)
		case !supportedCurveID && ok:
			t.Errorf("CurveToCurveID(%q) accepts an ID crypto/tls does not define", name)
		}
	}

	for name, id := range curveIDByName {
		if strings.HasPrefix(id.String(), "CurveID(") {
			t.Errorf("%q maps to an ID (0x%04x) that crypto/tls does not define", name, uint16(id))
		}
	}
}

func TestUnixSocketListener(t *testing.T) {
	t.Run("ids", func(t *testing.T) {
		socket, err := os.CreateTemp("", "socket")
		require.NoError(t, err)
		defer os.Remove(socket.Name())

		uid, gid := os.Getuid(), os.Getgid()

		u, err := osuser.LookupId(strconv.Itoa(uid))
		require.NoError(t, err)
		user := u.Username

		g, err := osuser.LookupGroupId(strconv.Itoa(gid))
		require.NoError(t, err)
		group := g.Name

		l, err := UnixSocketListener(socket.Name(), &UnixSocketsConfig{
			User:  user,
			Group: group,
			Mode:  "644",
		})
		require.NoError(t, err)
		defer l.Close()

		fi, err := os.Stat(socket.Name())
		require.NoError(t, err)

		mode, err := strconv.ParseUint("644", 8, 32)
		require.NoError(t, err)
		if fi.Mode().Perm() != os.FileMode(mode) {
			t.Fatal("failed to set permissions on the socket file")
		}
	})
	t.Run("names", func(t *testing.T) {
		socket, err := os.CreateTemp("", "socket")
		require.NoError(t, err)
		defer os.Remove(socket.Name())

		uid, gid := os.Getuid(), os.Getgid()
		l, err := UnixSocketListener(socket.Name(), &UnixSocketsConfig{
			User:  strconv.Itoa(uid),
			Group: strconv.Itoa(gid),
			Mode:  "644",
		})
		require.NoError(t, err)
		defer l.Close()

		fi, err := os.Stat(socket.Name())
		require.NoError(t, err)

		mode, err := strconv.ParseUint("644", 8, 32)
		require.NoError(t, err)
		if fi.Mode().Perm() != os.FileMode(mode) {
			t.Fatal("failed to set permissions on the socket file")
		}
	})
}

func TestSetFilePermissions(t *testing.T) {
	currentUID := strconv.Itoa(os.Getuid())
	currentGID := strconv.Itoa(os.Getgid())

	tests := []struct {
		name         string
		user         string
		group        string
		mode         string
		expectErr    bool
		expectedMode os.FileMode // Checked only when mode is specified
	}{
		{
			name:         "user+group+mode",
			user:         currentUID,
			group:        currentGID,
			mode:         "0644",
			expectErr:    false,
			expectedMode: 0o644,
		},
		{
			name:      "empty",
			user:      "",
			group:     "",
			mode:      "",
			expectErr: false,
		},
		{
			name:         "mode",
			user:         "",
			group:        "",
			mode:         "0600",
			expectErr:    false,
			expectedMode: 0o600,
		},
		{
			name:      "user+group",
			user:      currentUID,
			group:     currentGID,
			mode:      "",
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary file for each test case
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "testfile")

			err := os.WriteFile(tmpFile, []byte("content"), 0o666)
			require.NoError(t, err)

			err = setFilePermissions(tmpFile, tc.user, tc.group, tc.mode)
			require.NoError(t, err)
			require.Equal(t, tc.expectErr, err != nil)

			// Verify file mode when a mode was set
			if tc.mode != "" {
				info, err := os.Stat(tmpFile)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedMode, info.Mode().Perm())
			}
		})
	}
}
