// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/pluginutil/oci"
	"github.com/stretchr/testify/require"
)

// TestReconcileOCIPlugins tests the full OCI plugin reconciliation process
// This test downloads the real openbao-plugin-secrets-nomad from GHCR
func TestReconcileOCIPlugins(t *testing.T) {
	// Skip this test in short mode as it requires network access
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Skip if we're not on linux/amd64, this just avoids maintaining additional
	// hashes for plugin binaries down below.
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("system is not linux/amd64")
	}

	// Create a temporary directory for plugins
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	// The actual SHA256 of the Nomad plugin binary in ghcr.io/openbao/openbao-plugin-secrets-nomad:v0.1.4
	nomadPluginSHA256 := "04f9a349982449415037dbb8a7854250dea4e2328ff890cf767a5d38739699d4"

	// The actual SHA256 of the AWS plugin binary in ghcr.io/openbao/openbao-plugin-secrets-aws:v0.0.1
	awsPluginSHA256 := "c8d23e6d31be2a59d0c269bb7243158c4c61c5073f7ba50ce6f1a0050e023e2d"

	// Create a test configuration with the real Nomad plugin
	config := &server.Config{
		PluginDirectory: tempDir,
		Plugins: []*server.PluginConfig{
			{
				Type:       "secret",
				Name:       "nomad",
				Image:      name.MustParseReference("ghcr.io/openbao/openbao-plugin-secrets-nomad:v0.1.4"),
				Version:    "v0.1.4",
				BinaryName: "openbao-plugin-secrets-nomad",
				SHA256Sum:  nomadPluginSHA256,
			},
		},
		PluginDownloadBehavior: "continue", // Don't fail startup on download errors during testing
		PluginAutoDownload:     true,
	}

	// Create a test core
	core, _, _ := TestCoreUnsealed(t)
	core.pluginDirectory = tempDir
	core.pluginCatalog.directory = tempDir

	// Store the config
	core.rawConfig.Store(config)

	ctx := t.Context()

	// Download plugins.
	if err := oci.NewPluginDownloader(tempDir, config, core.logger).Reconcile(ctx); err != nil {
		t.Fatalf("OCI plugin download failed: %v", err)
	}

	// Verify the plugin was downloaded and symlinked correctly
	pluginPath := filepath.Join(tempDir, config.Plugins[0].FullName())

	// Check if the symlink exists
	linkInfo, err := os.Lstat(pluginPath)
	require.NoError(t, err)

	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected plugin to be a symlink")
	}

	// Verify the symlink points to the cache
	target, err := os.Readlink(pluginPath)
	require.NoError(t, err)

	// Should point to .oci-cache/
	expectedPrefix := ".oci-cache/"
	if !strings.HasPrefix(target, expectedPrefix) {
		t.Errorf("Symlink target should start with %q, got %q", expectedPrefix, target)
	}

	// Verify the cached file exists and is executable
	cachedPath := filepath.Join(tempDir, target)
	cachedInfo, err := os.Stat(cachedPath)
	require.NoError(t, err)

	if cachedInfo.Mode()&0o111 == 0 {
		t.Error("Cached plugin should be executable")
	}

	// Verify SHA256 of the downloaded plugin
	content, err := os.ReadFile(cachedPath)
	require.NoError(t, err)

	hash := sha256.Sum256(content)
	actualSHA256 := hex.EncodeToString(hash[:])

	if actualSHA256 != nomadPluginSHA256 {
		t.Errorf("SHA256 mismatch: expected %s, got %s", nomadPluginSHA256, actualSHA256)
	}

	// Register plugins automatically based on config.
	if err := core.registerDeclarativePlugins(ctx, false /* standby */); err != nil {
		t.Errorf("failed to register plugins: %v", err)
	}

	// Register plugins manually via plugin catalog.
	pluginType, _ := consts.ParsePluginType(config.Plugins[0].Type)
	pluginSha, _ := hex.DecodeString(config.Plugins[0].SHA256Sum)

	err = core.pluginCatalog.Set(t.Context(), config.Plugins[0].Name, pluginType, config.Plugins[0].Version, config.Plugins[0].FullName(), []string{}, []string{}, pluginSha, false)
	if err == nil {
		t.Errorf("expected failed to register OCI plugin without setting oci=true: %v", err)
	}

	err = core.pluginCatalog.Set(t.Context(), config.Plugins[0].Name, pluginType, config.Plugins[0].Version, config.Plugins[0].FullName(), []string{}, []string{}, pluginSha, true)
	if err != nil {
		t.Errorf("failed to register plugin: %v", err)
	}

	// Try to unregister it.
	err = core.pluginCatalog.Delete(t.Context(), config.Plugins[0].Name, pluginType, config.Plugins[0].Version)
	if err != nil {
		t.Errorf("failed to deregister plugin: %v", err)
	}

	// Update the config to add another plugin.
	config = &server.Config{
		PluginDirectory: tempDir,
		Plugins: []*server.PluginConfig{
			{
				Type:      "secret",
				Name:      "nomad",
				Image:     name.MustParseReference("ghcr.io/openbao/openbao-plugin-secrets-nomad:v0.1.4"),
				Version:   "v0.1.4",
				SHA256Sum: nomadPluginSHA256,
			},
			{
				Type:      "secret",
				Name:      "aws",
				Image:     name.MustParseReference("ghcr.io/openbao/openbao-plugin-secrets-aws:v0.0.1"),
				Version:   "v0.0.1",
				SHA256Sum: awsPluginSHA256,
			},
		},
		PluginDownloadBehavior: "continue", // Don't fail startup on download errors during testing
		PluginAutoDownload:     true,
		PluginAutoRegister:     true,
	}
	core.rawConfig.Store(config)

	// Re-download.
	if err := oci.NewPluginDownloader(tempDir, config, core.logger).Reconcile(ctx); err != nil {
		t.Fatalf("OCI plugin reconciliation failed: %v", err)
	}

	// Reconcile, but this time use the SIGHUP handler.
	core.ReloadPlugins()

	// We should have both nomad and aws in our list.
	list, err := core.pluginCatalog.ListVersionedPlugins(ctx, pluginType)
	require.NoErrorf(t, err, "failed to list plugins after additions")

	for _, name := range []string{"nomad", "aws"} {
		found := false
		for _, plugin := range list {
			if plugin.Name == name {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("failed to find %v plugins catalog:\nlist: %#v", name, list)
		}
	}

	// Now remove them from the config and ensure they're deregistered.
	config = &server.Config{
		PluginDirectory:        tempDir,
		Plugins:                []*server.PluginConfig{},
		PluginDownloadBehavior: "continue", // Don't fail startup on download errors during testing
		PluginAutoDownload:     true,
		PluginAutoRegister:     true,
	}
	core.rawConfig.Store(config)

	// Reconcile, but this time use the SIGHUP handler.
	core.ReloadPlugins()

	// We should have both nomad and aws in our list.
	list, err = core.pluginCatalog.ListVersionedPlugins(ctx, pluginType)
	require.NoErrorf(t, err, "failed to list plugins after removal")

	for _, name := range []string{"nomad", "aws"} {
		found := false
		for _, plugin := range list {
			if plugin.Name == name {
				found = true
				break
			}
		}

		if found {
			t.Fatalf("unexpectedly found %v plugin in catalog after removal from config:\nlist: %#v", name, list)
		}
	}
}
