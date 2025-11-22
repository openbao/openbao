// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/pluginutil/oci"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

// createTestOCIImage creates a test OCI image with a plugin binary
func createTestOCIImage(t *testing.T, binaryName, binaryContent string) v1.Image {
	// Create a tar layer with our test binary
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add the plugin binary to the tar
	header := &tar.Header{
		Name:     binaryName,
		Mode:     0o755,
		Size:     int64(len(binaryContent)),
		Typeflag: tar.TypeReg,
	}

	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}

	if _, err := tw.Write([]byte(binaryContent)); err != nil {
		t.Fatalf("failed to write binary content: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	// Create the layer directly from the tar data (uncompressed)
	layer := static.NewLayer(buf.Bytes(), "application/vnd.docker.image.rootfs.diff.tar")

	// Start with an empty image and add our layer
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("failed to create image: %v", err)
	}

	return img
}

// TestExtractPluginFromImage tests the OCI image extraction functionality
func TestExtractPluginFromImage(t *testing.T) {
	tests := []struct {
		name          string
		binaryName    string
		binaryContent string
		targetBinary  string
		expectError   bool
	}{
		{
			name:          "exact match",
			binaryName:    "test-plugin",
			binaryContent: "test binary content",
			targetBinary:  "test-plugin",
			expectError:   false,
		},
		{
			name:          "with leading slash",
			binaryName:    "/test-plugin",
			binaryContent: "test binary content",
			targetBinary:  "test-plugin",
			expectError:   false,
		},
		{
			name:          "not found",
			binaryName:    "different-plugin",
			binaryContent: "test binary content",
			targetBinary:  "missing-plugin",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for the test
			tempDir, err := os.MkdirTemp("", "oci-plugin-test")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir) //nolint:errcheck

			// Create the test OCI image
			img := createTestOCIImage(t, tt.binaryName, tt.binaryContent)

			// Create a minimal config and downloader for testing
			logger := hclog.NewNullLogger()
			config := &server.Config{}
			downloader := oci.NewPluginDownloader(tempDir, config, logger)

			// Test the extraction
			targetPath := filepath.Join(tempDir, "extracted-plugin")
			err = downloader.ExtractPluginFromImage(img, targetPath, tt.targetBinary, logger)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify the file was created
			if _, err := os.Stat(targetPath); os.IsNotExist(err) {
				t.Error("expected file was not created")
				return
			}

			// Verify the content
			content, err := os.ReadFile(targetPath)
			if err != nil {
				t.Fatalf("failed to read extracted file: %v", err)
			}

			if string(content) != tt.binaryContent {
				t.Errorf("content mismatch: expected %q, got %q", tt.binaryContent, string(content))
			}
		})
	}
}

// TestReconcileOCIPlugins tests the full OCI plugin reconciliation process
// This test downloads the real openbao-plugin-secrets-nomad from GHCR
func TestReconcileOCIPlugins(t *testing.T) {
	// Skip this test in short mode as it requires network access
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a temporary directory for plugins
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// The actual SHA256 of the Nomad plugin binary in ghcr.io/openbao/openbao-plugin-secrets-nomad:v0.1.4
	nomadPluginSHA256 := "04f9a349982449415037dbb8a7854250dea4e2328ff890cf767a5d38739699d4"

	// Create a test configuration with the real Nomad plugin
	config := &server.Config{
		PluginDirectory: tempDir,
		Plugins: []*server.PluginConfig{
			{
				Type:       "secret",
				Name:       "nomad",
				Image:      "ghcr.io/openbao/openbao-plugin-secrets-nomad",
				Version:    "v0.1.4",
				BinaryName: "openbao-plugin-secrets-nomad",
				SHA256Sum:  nomadPluginSHA256,
			},
		},
		PluginDownloadBehavior: "continue", // Don't fail startup on download errors during testing
	}

	// Create a test core
	core, _, _ := TestCoreUnsealed(t)
	core.pluginDirectory = tempDir
	core.pluginCatalog.directory = tempDir

	// Store the config
	core.rawConfig.Store(config)

	// Test the OCI plugin reconciliation
	ctx := context.Background()
	err = core.reconcileOCIPlugins(ctx)
	// Verify the download worked
	if err != nil {
		t.Fatalf("OCI plugin reconciliation failed: %v", err)
	}

	// Verify the plugin was downloaded and symlinked correctly
	pluginPath := filepath.Join(tempDir, config.Plugins[0].FullName())

	// Check if the symlink exists
	linkInfo, err := os.Lstat(pluginPath)
	if err != nil {
		t.Fatalf("Plugin symlink not found: %v", err)
	}

	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected plugin to be a symlink")
	}

	// Verify the symlink points to the cache
	target, err := os.Readlink(pluginPath)
	if err != nil {
		t.Fatalf("Failed to read symlink: %v", err)
	}

	// Should point to .oci-cache/secret-nomad/{sha256_prefix}/openbao-plugin-secrets-nomad
	expectedPrefix := ".oci-cache/secret-nomad/"
	if !strings.HasPrefix(target, expectedPrefix) {
		t.Errorf("Symlink target should start with %q, got %q", expectedPrefix, target)
	}

	// Verify the cached file exists and is executable
	cachedPath := filepath.Join(tempDir, target)
	cachedInfo, err := os.Stat(cachedPath)
	if err != nil {
		t.Fatalf("Cached plugin file not found: %v", err)
	}

	if cachedInfo.Mode()&0o111 == 0 {
		t.Error("Cached plugin should be executable")
	}

	// Verify SHA256 of the downloaded plugin
	content, err := os.ReadFile(cachedPath)
	if err != nil {
		t.Fatalf("Failed to read cached plugin: %v", err)
	}

	hash := sha256.Sum256(content)
	actualSHA256 := hex.EncodeToString(hash[:])

	if actualSHA256 != nomadPluginSHA256 {
		t.Errorf("SHA256 mismatch: expected %s, got %s", nomadPluginSHA256, actualSHA256)
	}

	// Try to register downloaded plugin
	pluginType, _ := consts.ParsePluginType(config.Plugins[0].Type)
	pluginSha, _ := hex.DecodeString(config.Plugins[0].SHA256Sum)
	err = core.pluginCatalog.Set(context.Background(), config.Plugins[0].Name, pluginType, config.Plugins[0].Version, config.Plugins[0].FullName(), []string{}, []string{}, pluginSha)
	if err != nil {
		t.Errorf("failed to register plugin: %v", err)
	}
}

// TestPluginCacheStructure tests the new hidden cache structure and symlink functionality
func TestPluginCacheStructure(t *testing.T) {
	// Create a temporary directory for plugins
	tempDir, err := os.MkdirTemp("", "oci-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck

	// Test plugin configuration
	pluginConfig := &server.PluginConfig{
		Image:      "docker.io/test/plugin",
		Version:    "latest",
		Type:       "test",
		Name:       "plugin",
		BinaryName: "test-plugin",
		SHA256Sum:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // SHA256 of "test"
	}

	// Manually create the expected cache structure to test validation
	sha256Prefix := pluginConfig.SHA256Sum[:8] // "9f86d081"
	cacheDir := filepath.Join(tempDir, ".oci-cache", pluginConfig.Slug(), sha256Prefix)
	cachedPluginPath := filepath.Join(cacheDir, pluginConfig.BinaryName)

	// Create the cache directory
	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create cache directory: %v", err)
	}

	// Create a test plugin file in cache with the expected content
	testContent := []byte("test")
	err = os.WriteFile(cachedPluginPath, testContent, 0o755)
	if err != nil {
		t.Fatalf("failed to create cached plugin file: %v", err)
	}

	// Create symlink in plugin directory
	symlinkPath := filepath.Join(tempDir, pluginConfig.FullName())
	relativeTarget := filepath.Join(".oci-cache", "test-plugin", sha256Prefix, "test-plugin")
	err = os.Symlink(relativeTarget, symlinkPath)
	if err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Test that cache validation works with symlinks using the OCI downloader
	config := &server.Config{}
	downloader := oci.NewPluginDownloader(tempDir, config, hclog.NewNullLogger())
	isValid := downloader.IsPluginCacheValid(pluginConfig)
	if !isValid {
		t.Error("Expected plugin cache to be valid with symlink")
	}
}
