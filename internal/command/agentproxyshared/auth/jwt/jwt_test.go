// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"bytes"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/command/agentproxyshared/auth"
	"github.com/stretchr/testify/require"
)

func TestIngressToken(t *testing.T) {
	const (
		dir       = "dir"
		file      = "file"
		empty     = "empty"
		missing   = "missing"
		symlinked = "symlinked"
	)

	setupTestDir := func() string {
		testDir := t.TempDir()
		err := os.WriteFile(path.Join(testDir, file), []byte("test"), 0o644)
		require.NoError(t, err)
		_, err = os.Create(path.Join(testDir, empty))
		require.NoError(t, err)
		err = os.Mkdir(path.Join(testDir, dir), 0o755)
		require.NoError(t, err)
		err = os.Symlink(path.Join(testDir, file), path.Join(testDir, symlinked))
		require.NoError(t, err)

		return testDir
	}

	for _, tc := range []struct {
		name      string
		path      string
		errString string
	}{
		{
			"happy path",
			file,
			"",
		},
		{
			"path is directory",
			dir,
			"[ERROR] jwt file is not a regular file or symlink",
		},
		{
			"path is symlink",
			symlinked,
			"",
		},
		{
			"path is missing (implies nothing for ingressToken to do)",
			missing,
			"",
		},
		{
			"path is empty file",
			empty,
			"[WARN]  empty jwt file read",
		},
	} {
		testDir := setupTestDir()
		logBuffer := bytes.Buffer{}
		jwtAuth := &jwtMethod{
			logger: hclog.New(&hclog.LoggerOptions{
				Output: &logBuffer,
			}),
			path: path.Join(testDir, tc.path),
		}

		jwtAuth.ingressToken()

		if tc.errString != "" {
			if !strings.Contains(logBuffer.String(), tc.errString) {
				t.Fatal("logs did no contain expected error", tc.errString, logBuffer.String())
			}
		} else {
			if strings.Contains(logBuffer.String(), "[ERROR]") || strings.Contains(logBuffer.String(), "[WARN]") {
				t.Fatal("logs contained unexpected error", logBuffer.String())
			}
		}
	}
}

func TestDeleteAfterReading(t *testing.T) {
	for _, tc := range map[string]struct {
		configValue  string
		shouldDelete bool
	}{
		"default": {
			"",
			true,
		},
		"explicit true": {
			"true",
			true,
		},
		"false": {
			"false",
			false,
		},
	} {
		rootDir := t.TempDir()
		tokenPath := path.Join(rootDir, "token")
		err := os.WriteFile(tokenPath, []byte("test"), 0o644)
		require.NoError(t, err)

		config := &auth.AuthConfig{
			Config: map[string]any{
				"path": tokenPath,
				"role": "unusedrole",
			},
			Logger: hclog.Default(),
		}
		if tc.configValue != "" {
			config.Config["remove_jwt_after_reading"] = tc.configValue
		}

		jwtAuth, err := NewJWTAuthMethod(config)
		require.NoError(t, err)

		jwtAuth.(*jwtMethod).ingressToken()

		if _, err := os.Lstat(tokenPath); tc.shouldDelete {
			if err == nil || !os.IsNotExist(err) {
				t.Fatal(err)
			}
		} else {
			require.NoError(t, err)
		}
	}
}

func TestDeleteAfterReadingSymlink(t *testing.T) {
	for _, tc := range map[string]struct {
		configValue              string
		shouldDelete             bool
		removeJWTFollowsSymlinks bool
	}{
		"default": {
			"",
			true,
			false,
		},
		"explicit true": {
			"true",
			true,
			false,
		},
		"false": {
			"false",
			false,
			false,
		},
		"default + removeJWTFollowsSymlinks": {
			"",
			true,
			true,
		},
		"explicit true + removeJWTFollowsSymlinks": {
			"true",
			true,
			true,
		},
		"false + removeJWTFollowsSymlinks": {
			"false",
			false,
			true,
		},
	} {
		rootDir := t.TempDir()
		tokenPath := path.Join(rootDir, "token")
		err := os.WriteFile(tokenPath, []byte("test"), 0o644)
		require.NoError(t, err)

		symlink, err := os.CreateTemp("", "auth.jwt.symlink.test.")
		require.NoError(t, err)
		symlinkName := symlink.Name()
		symlink.Close()
		os.Remove(symlinkName)
		os.Symlink(tokenPath, symlinkName)

		config := &auth.AuthConfig{
			Config: map[string]any{
				"path": symlinkName,
				"role": "unusedrole",
			},
			Logger: hclog.Default(),
		}
		if tc.configValue != "" {
			config.Config["remove_jwt_after_reading"] = tc.configValue
		}
		config.Config["remove_jwt_follows_symlinks"] = tc.removeJWTFollowsSymlinks

		jwtAuth, err := NewJWTAuthMethod(config)
		require.NoError(t, err)

		jwtAuth.(*jwtMethod).ingressToken()

		pathToCheck := symlinkName
		if tc.removeJWTFollowsSymlinks {
			pathToCheck = tokenPath
		}
		if _, err := os.Lstat(pathToCheck); tc.shouldDelete {
			if err == nil || !os.IsNotExist(err) {
				t.Fatal(err)
			}
		} else {
			require.NoError(t, err)
		}
	}
}
