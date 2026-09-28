// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/stretchr/testify/require"
)

const (
	// We test downloads against this plugin because it's small.
	pluginImage = "ghcr.io/openbao/openbao-plugin-kms-ovhcloud:v0.0.1"

	// The multi-arch digest of the above.
	pluginImageDigest = "sha256:0ac993bbd5589845ef0b60f9b106ebadf82903de8bccaafce8abb04d7094d9ed"

	// The binary sha256sum for linux/amd64.
	pluginBinarySHA256Sum = "653ed969ae963caa3622c4505be401756a91c8cd2145ac83b83249648b60f76c"

	// To inject bad digests.
	zeroImageDigest = "sha256:" + zeroSHA256Sum
	zeroSHA256Sum   = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	pluginConfigDigest = server.PluginConfig{
		Type:    "kms",
		Name:    "ovhcloud",
		Version: "v0.0.1",
		Image:   name.MustParseReference(pluginImage + "@" + pluginImageDigest),
	}

	pluginConfigSHA256Sum = server.PluginConfig{
		Type:      "kms",
		Name:      "ovhcloud",
		Version:   "v0.0.1",
		Image:     name.MustParseReference(pluginImage),
		SHA256Sum: pluginBinarySHA256Sum,
	}

	pluginConfigDigestAndSHA256Sum = server.PluginConfig{
		Type:      "kms",
		Name:      "ovhcloud",
		Version:   "v0.0.1",
		Image:     name.MustParseReference(pluginImage + "@" + pluginImageDigest),
		SHA256Sum: pluginBinarySHA256Sum,
	}

	pluginConfigBadDigest = server.PluginConfig{
		Type:    "kms",
		Name:    "ovhcloud",
		Version: "v0.0.1",
		Image:   name.MustParseReference(pluginImage + "@" + zeroImageDigest),
	}

	pluginConfigBadSHA256Sum = server.PluginConfig{
		Type:      "kms",
		Name:      "ovhcloud",
		Version:   "v0.0.1",
		Image:     name.MustParseReference(pluginImage),
		SHA256Sum: zeroSHA256Sum,
	}

	// This is disallowed by server config validation, but still supported by
	// the downloader.
	pluginConfigUnpinned = server.PluginConfig{
		Type:    "kms",
		Name:    "ovhcloud",
		Version: "v0.0.1",
		Image:   name.MustParseReference(pluginImage),
	}
)

func TestDownload(t *testing.T) {
	for name, tt := range map[string]struct {
		config server.PluginConfig
		err    bool // Test should fail?
	}{
		"digest":           {config: pluginConfigDigest},
		"sha256sum":        {config: pluginConfigSHA256Sum},
		"digest+sha256sum": {config: pluginConfigDigestAndSHA256Sum},
		"baddigest":        {config: pluginConfigBadDigest, err: true},
		"badsha256sum":     {config: pluginConfigBadSHA256Sum, err: true},
		"unpinned":         {config: pluginConfigUnpinned},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// If we've got a sha256sum and we're not running on linux/amd64,
			// skip since the test won't possibly pass.
			if len(tt.config.SHA256Sum) > 0 && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
				t.Skip("system is not linux/amd64")
			}

			dir := t.TempDir()
			logger := hclog.Default()

			downloader := NewPluginDownloader(dir, &server.Config{}, logger)
			err := downloader.Download(t.Context(), &tt.config, logger)

			out := filepath.Join(dir, PluginCacheDir, pluginImageDigest)

			if tt.err {
				require.Error(t, err)
				require.NoFileExists(t, out)
			} else {
				require.NoError(t, err)
				require.FileExists(t, out)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	// Helper to create a v1.Image with a single layer that has a single file.
	image := func(t *testing.T, path, content string) v1.Image {
		t.Helper()

		// Create a tar layer with our test path + content.
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)

		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: path,
			Size: int64(len(content)),
		}))

		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
		require.NoError(t, tw.Close())

		// Add the layer to an image. Note that types.OCILayer technically
		// represents a gzipped layer, but static requires that the layer is
		// passed uncompressed.
		layer := static.NewLayer(buf.Bytes(), types.OCILayer)
		img, err := mutate.AppendLayers(empty.Image, layer)
		require.NoError(t, err)

		return img
	}

	for name, tt := range map[string]struct {
		path   string // Path to create within the image.
		target string // Path to attempt extraction of.
		err    bool   // Test should fail?
	}{
		"exact":    {path: "test-plugin", target: "test-plugin"},
		"slash":    {path: "/test-plugin", target: "test-plugin"},
		"notfound": {path: "test-plugin", target: "missing-plugin", err: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			logger := hclog.Default()
			downloader := NewPluginDownloader(dir, &server.Config{}, logger)

			const content = "foobar"
			img := image(t, tt.path, content)
			out := filepath.Join(t.TempDir(), "plugin")

			err := downloader.extract(img, out, tt.target, logger)

			if tt.err {
				require.Error(t, err)
				require.NoFileExists(t, out)
				return
			}

			require.NoError(t, err)
			require.FileExists(t, out)

			have, err := os.ReadFile(out)
			require.NoError(t, err)
			require.Equal(t, content, string(have))
		})
	}
}

func TestIsCached(t *testing.T) {
	for name, tt := range map[string]struct {
		config  server.PluginConfig
		path    string // Path to write / link to within the OCI cache dir.
		create  bool   // Whether to create the above path.
		symlink bool   // Whether to symlink to the above path.
		cached  bool   // Whether we expect it to count as cached.
	}{
		"empty1": {
			config: pluginConfigDigest,
		},
		"empty2": {
			config: pluginConfigSHA256Sum,
		},
		"nolink": {
			config: pluginConfigSHA256Sum,
			path:   pluginImageDigest,
			create: true,
		},
		"nofile": {
			config:  pluginConfigSHA256Sum,
			path:    pluginImageDigest,
			symlink: true,
		},
		"badname": {
			config: pluginConfigDigest,
			path:   zeroImageDigest,
			create: true, symlink: true,
		},
		"badsha256sum": {
			config: pluginConfigBadSHA256Sum,
			path:   pluginImageDigest,
			create: true, symlink: true,
		},
		"good1": {
			config: pluginConfigDigest,
			path:   pluginImageDigest,
			create: true, symlink: true, cached: true,
		},
		"good2": {
			config: pluginConfigSHA256Sum,
			path:   pluginImageDigest,
			create: true, symlink: true, cached: true,
		},
		"good3": {
			config: pluginConfigDigestAndSHA256Sum,
			path:   pluginImageDigest,
			create: true, symlink: true, cached: true,
		},
		"legacy": {
			config: pluginConfigSHA256Sum,
			path:   "some/deeper/path",
			create: true, symlink: true, cached: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			logger := hclog.Default()

			content := []byte("foobar")
			if len(tt.config.SHA256Sum) > 0 && tt.config.SHA256Sum != zeroSHA256Sum {
				// If set, exchange the sha256sum for a value we control so we
				// don't need to write the actual plugin binary to disk.
				digest := sha256.Sum256(content)
				tt.config.SHA256Sum = hex.EncodeToString(digest[:])
			}

			target := filepath.Join(dir, PluginCacheDir, tt.path)

			if tt.create {
				require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				require.NoError(t, os.WriteFile(target, content, 0o644))
			}

			if tt.symlink {
				target, err := filepath.Rel(dir, target)
				require.NoError(t, err)
				require.NoError(t, os.Symlink(target, filepath.Join(dir, tt.config.FullName())))
			}

			downloader := NewPluginDownloader(dir, &server.Config{}, logger)
			require.Equal(t, tt.cached, downloader.IsCached(&tt.config))
		})
	}
}

func TestPrune(t *testing.T) {
	config := &server.Config{
		// We only need partial configs since Prune operates offline and doesn't
		// use checksums.
		Plugins: []*server.PluginConfig{
			{Type: "secret", Name: "aws", Version: "v0.2.0"},
			{Type: "kms", Name: "pkcs11", Version: "v0.2.0"},
		},
	}

	dir := t.TempDir()
	downloader := NewPluginDownloader(dir, config, hclog.Default())

	// Helper to create an empty file, including required directories.
	touch := func(t *testing.T, path string) {
		t.Helper()
		path = filepath.Join(dir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, nil, 0o644))
	}

	// Helper to create a symlink.
	symlink := func(t *testing.T, from, to string) {
		t.Helper()
		require.NoError(t, os.Symlink(to, filepath.Join(dir, from)))
	}

	// Helper to snapshot a file tree, ignoring directory entries.
	snapshot := func(t *testing.T, root string) (files []string) {
		t.Helper()
		require.NoError(t, filepath.WalkDir(root, func(
			path string, d fs.DirEntry, err error,
		) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(root, path)
			require.NoError(t, err)
			files = append(files, rel)
			return nil
		}))
		sort.Strings(files)
		return files
	}

	// A plugin referenced by the config.
	touch(t, ".oci-cache/sha256:secret-aws-v0.2.0")
	symlink(t, "secret-aws-v0.2.0", ".oci-cache/sha256:secret-aws-v0.2.0")
	// A plugin symlinked to some unrelated path.
	symlink(t, "kms-ovhcloud-v0.0.1", t.TempDir())
	// A symlink to the above symlink, within the plugin directory.
	symlink(t, "kms-ovhcloud-v0.0.2", filepath.Join(dir, "kms-ovhcloud-v0.0.1"))
	// A manually installed plugin that isn't a symlink.
	touch(t, "kms-pkcs11-v0.1.0")

	// A cache entry with no link pointing at it.
	touch(t, ".oci-cache/sha256:nothing")
	// A stale link into the OCI cache.
	symlink(t, "secret-azure-v0.1.0", ".oci-cache/sha256:nowhere")
	// An old plugin version.
	touch(t, ".oci-cache/sha256:secret-aws-v0.1.0")
	symlink(t, "secret-aws-v0.1.0", ".oci-cache/sha256:secret-aws-v0.1.0")

	// Verify our work above.
	require.Equal(t, []string{
		".oci-cache/sha256:nothing",
		".oci-cache/sha256:secret-aws-v0.1.0",
		".oci-cache/sha256:secret-aws-v0.2.0",
		"kms-ovhcloud-v0.0.1",
		"kms-ovhcloud-v0.0.2",
		"kms-pkcs11-v0.1.0",
		"secret-aws-v0.1.0",
		"secret-aws-v0.2.0",
		"secret-azure-v0.1.0",
	}, snapshot(t, dir))

	// Prune, then check the snapshot again.
	require.NoError(t, downloader.Prune())

	require.Equal(t, []string{
		".oci-cache/sha256:secret-aws-v0.2.0",
		"kms-ovhcloud-v0.0.1",
		"kms-ovhcloud-v0.0.2",
		"kms-pkcs11-v0.1.0",
		"secret-aws-v0.2.0",
	}, snapshot(t, dir))
}
