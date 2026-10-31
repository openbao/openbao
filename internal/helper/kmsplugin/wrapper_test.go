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
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/osutil"
	cataloghelper "github.com/openbao/openbao/v2/internal/helper/pluginutil/catalog"
	"github.com/stretchr/testify/require"
)

const TestPluginServerEnv = "BAO_TEST_PLUGIN_SERVER"

// TestStaticPluginServer runs a plugin that serves the static wrapper.
func TestStaticPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	gkwplugin.Serve(&gkwplugin.ServeOpts{
		WrapperFactoryFunc: builtinWrappers["static"],
	})
}

// TestTransitPluginServer runs a plugin that serves the Transit KMS.
func TestTransitPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	gkwplugin.Serve(&gkwplugin.ServeOpts{
		KMSFactoryFunc: builtinKMSes["transit"],
		Metadata:       builtinMetadata["transit"],
	})
}

var StaticPluginConfig = &server.PluginConfig{
	Name: "static",
	Args: []string{"-test.run=TestStaticPluginServer"},
}

var TransitPluginConfig = &server.PluginConfig{
	Name: "transit",
	Args: []string{"-test.run=TestTransitPluginServer"},
}

func init() {
	command := filepath.Base(os.Args[0])

	sha256sum, err := osutil.FileSha256Sum(os.Args[0])
	if err != nil {
		panic(err)
	}

	for _, config := range []*server.PluginConfig{
		StaticPluginConfig,
		TransitPluginConfig,
	} {
		config.Type = consts.PluginTypeKMS.String()
		config.Command = command
		config.SHA256Sum = sha256sum
		config.Env = []string{TestPluginServerEnv + "=1"}
	}
}

// TestConfigureWrapper tests creating, configuring and finalizing a pluginized
// wrapper.
func TestConfigureWrapper(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{StaticPluginConfig},
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
	require.IsType(t, &remoteWrapper{}, w1, "wrapper should be external")

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
	require.IsType(t, &remoteWrapper{}, w1, "wrapper should be external")

	c1 := w1.(*remoteWrapper).client
	require.NoError(t, w1.(wrapping.InitFinalizer).Finalize(ctx), "should finalize gracefully")
	require.NoError(t, c1.Ping(), "client should still be alive")

	_, err = w1.Encrypt(ctx, plaintext)
	require.Error(t, err, "finalized wrapper should not work despite client still being alive")

	blob, err = w2.Encrypt(ctx, plaintext)
	require.NoError(t, err, "should encrypt plaintext")
	output, err = w2.Decrypt(ctx, blob)
	require.NoError(t, err, "should decrypt blob")
	require.Equal(t, plaintext, output, "decrypted blob should equal original plaintext")

	c2 := w2.(*remoteWrapper).client
	require.NoError(t, w2.(wrapping.InitFinalizer).Finalize(ctx), "should finalize gracefully")
	require.Error(t, c2.Ping(), "client should not be reachable")
}

// TestReloadWrapper tests automatically reloading a wrapper and replaying its
// state after closing the underlying client.
func TestReloadWrapper(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{StaticPluginConfig},
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
	require.IsType(t, &remoteWrapper{}, w1, "wrapper should be external")

	w2, _, err := catalog.ConfigureWrapper(ctx, "static",
		wrapping.WithConfigMap(map[string]string{
			"current_key":    hex.EncodeToString(key),
			"current_key_id": "current",
		}))
	require.NoError(t, err, "should configure wrapper successfully")
	require.NotNil(t, w2, "should return a wrapper")
	require.IsType(t, &remoteWrapper{}, w2, "wrapper should be external")

	blob, err := w1.Encrypt(ctx, plaintext)
	require.NoError(t, err, "should encrypt plaintext")

	// Kill the underlying plugin process that serves both wrappers:
	cataloghelper.TestKillClient(t, w1.(*remoteWrapper).client)

	output, err := w1.Decrypt(ctx, blob)
	require.NoError(t, err, "should decrypt blob with reloaded wrapper")
	require.Equal(t, plaintext, output, "decrypted blob should equal original plaintext")

	require.NotEqual(t, w2.(*remoteWrapper).client, w1.(*remoteWrapper).client, "wrapper should have a new client")
	require.NoError(t, w2.(wrapping.InitFinalizer).Finalize(ctx), "should not fail to finalize wrapper that did not reload")

	c1 := w1.(*remoteWrapper).client
	require.NoError(t, w1.(wrapping.InitFinalizer).Finalize(ctx), "should finalize reloaded wrapper")
	require.Error(t, c1.Ping(), "client should not be reachable")
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
	require.IsNotType(t, &remoteWrapper{}, w, "wrapper should not be external")
}
