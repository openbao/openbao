// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/stretchr/testify/require"
)

// TestConfigureWrapper tests creating, configuring and finalizing a pluginized
// wrapper.
func TestConfigureWrapper(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{testPluginConfig(t)},
	})
	require.NoError(t, err, "catalog should create successfully")

	w1, config, err := catalog.ConfigureWrapper(ctx, "static")
	require.Error(t, err, "should error for missing config")
	require.Nil(t, config, "should not return a config")
	require.Nil(t, w1, "should not return a wrapper")

	plaintext := []byte("foo")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	w1, config, err = catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, config, "should return a config")
	require.NotNil(t, w1, "should return a wrapper")
	require.IsType(t, &wrapper{}, w1, "wrapper should be external")

	blob, err := w1.Encrypt(ctx, plaintext)
	require.NoError(t, err, "should encrypt plaintext")
	output, err := w1.Decrypt(ctx, blob)
	require.NoError(t, err, "should decrypt blob")
	require.Equal(t, plaintext, output, "decrypted blob should equal original plaintext")

	w2, config, err := catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, config, "should return a config")
	require.NotNil(t, w2, "should return a wrapper")
	require.IsType(t, &wrapper{}, w1, "wrapper should be external")

	require.NoError(t, w1.(wrapping.InitFinalizer).Finalize(ctx), "should finalize gracefully")
	require.Len(t, catalog.clients, 1, "should keep the plugin client alive")

	_, err = w1.Encrypt(ctx, plaintext)
	require.Error(t, err, "finalized wrapper should not work despite client still being alive")

	blob, err = w2.Encrypt(ctx, plaintext)
	require.NoError(t, err, "should encrypt plaintext")
	output, err = w2.Decrypt(ctx, blob)
	require.NoError(t, err, "should decrypt blob")
	require.Equal(t, plaintext, output, "decrypted blob should equal original plaintext")

	require.NoError(t, w2.(wrapping.InitFinalizer).Finalize(ctx), "should finalize gracefully")
	require.Len(t, catalog.clients, 0, "should have no more plugin clients")
}

// TestReloadWrapper tests automatically reloading a wrapper and replaying its
// state after closing the underlying client.
func TestReloadWrapper(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{testPluginConfig(t)},
	})
	require.NoError(t, err, "catalog should create successfully")

	plaintext := []byte("foo")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	w1, _, err := catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, w1, "should return a wrapper")
	require.IsType(t, &wrapper{}, w1, "wrapper should be external")

	w2, _, err := catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, w2, "should return a wrapper")
	require.IsType(t, &wrapper{}, w2, "wrapper should be external")

	blob, err := w1.Encrypt(ctx, plaintext)
	require.NoError(t, err, "should encrypt plaintext")

	// Kill the underlying plugin process that serves both wrappers:
	w1.(*wrapper).client.process.Kill()

	output, err := w1.Decrypt(ctx, blob)
	require.NoError(t, err, "should decrypt blob with reloaded wrapper")
	require.Equal(t, plaintext, output, "decrypted blob should equal original plaintext")

	require.NoError(t, w2.(wrapping.InitFinalizer).Finalize(ctx), "should not fail to finalize wrapper that did not reload")
	require.Len(t, catalog.clients, 1, "should keep the plugin client alive")

	require.NoError(t, w1.(wrapping.InitFinalizer).Finalize(ctx), "should finalize reloaded wrapper")
	require.Len(t, catalog.clients, 0, "should have no more plugin clients")
}

// TestBuiltinWrapper tests that a builtin wrapper is returned as fallback when
// an external wrapper is unavailable.
func TestBuiltinWrapper(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	catalog, err := NewCatalog(logger, &server.Config{})
	require.NoError(t, err, "catalog should create successfully")

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	w, config, err := catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, config, "should return a config")
	require.NotNil(t, w, "should return a wrapper")
	require.IsNotType(t, &wrapper{}, w, "wrapper should not be external")
}
