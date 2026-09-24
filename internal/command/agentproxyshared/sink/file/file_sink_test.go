// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package file

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/v2/internal/command/agentproxyshared/sink"
	"github.com/stretchr/testify/require"
)

func testFileSink(t *testing.T, log hclog.Logger) (*sink.SinkConfig, string) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token")

	config := &sink.SinkConfig{
		Logger: log.Named("sink.file"),
		Config: map[string]any{
			"path": path,
		},
	}

	s, err := NewFileSink(config)
	require.NoError(t, err)
	config.Sink = s

	return config, tmpDir
}

func TestFileSink(t *testing.T) {
	log := logging.NewVaultLogger(hclog.Trace)

	fs, tmpDir := testFileSink(t, log)

	path := filepath.Join(tmpDir, "token")

	uuidStr, _ := uuid.GenerateUUID()
	if err := fs.WriteToken(uuidStr); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	require.NoError(t, err)

	fi, err := file.Stat()
	require.NoError(t, err)
	if fi.Mode() != os.FileMode(0o640) {
		t.Fatalf("wrong file mode was detected at %s", path)
	}
	err = file.Close()
	require.NoError(t, err)

	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	if string(fileBytes) != uuidStr {
		t.Fatalf("expected %s, got %s", uuidStr, string(fileBytes))
	}
}

func testFileSinkMode(t *testing.T, log hclog.Logger) (*sink.SinkConfig, string) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token")

	config := &sink.SinkConfig{
		Logger: log.Named("sink.file"),
		Config: map[string]any{
			"path": path,
			"mode": 0o644,
		},
	}

	s, err := NewFileSink(config)
	require.NoError(t, err)
	config.Sink = s

	return config, tmpDir
}

func TestFileSinkMode(t *testing.T) {
	log := logging.NewVaultLogger(hclog.Trace)

	fs, tmpDir := testFileSinkMode(t, log)

	path := filepath.Join(tmpDir, "token")

	uuidStr, _ := uuid.GenerateUUID()
	if err := fs.WriteToken(uuidStr); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	fi, err := file.Stat()
	require.NoError(t, err)
	if fi.Mode() != os.FileMode(0o644) {
		t.Fatalf("wrong file mode was detected at %s", path)
	}

	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	if string(fileBytes) != uuidStr {
		t.Fatalf("expected %s, got %s", uuidStr, string(fileBytes))
	}
}

func testFileSinkChown(t *testing.T, log hclog.Logger) (*sink.SinkConfig, string) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token")

	config := &sink.SinkConfig{
		Logger: log.Named("sink.file"),
		Config: map[string]any{
			"path": path,
			"uid":  os.Getuid(),
			"gid":  os.Getgid(),
		},
	}

	s, err := NewFileSink(config)
	require.NoError(t, err)
	config.Sink = s

	return config, tmpDir
}

func TestFileSinkChown(t *testing.T) {
	log := logging.NewVaultLogger(hclog.Trace)

	fs, tmpDir := testFileSinkChown(t, log)
	path := filepath.Join(tmpDir, "token")

	uuidStr, _ := uuid.GenerateUUID()
	if err := fs.WriteToken(uuidStr); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close() //nolint:errcheck

	fi, err := file.Stat()
	require.NoError(t, err)

	stat := fi.Sys().(*syscall.Stat_t)
	if stat.Uid != uint32(os.Getuid()) {
		t.Fatalf("expected uid %d, got %d", os.Getuid(), stat.Uid)
	}
	if stat.Gid != uint32(os.Getgid()) {
		t.Fatalf("expected gid %d, got %d", os.Getgid(), stat.Gid)
	}

	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	if string(fileBytes) != uuidStr {
		t.Fatalf("expected %s, got %s", uuidStr, string(fileBytes))
	}
}
