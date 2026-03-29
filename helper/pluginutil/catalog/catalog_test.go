// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/osutil"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stretchr/testify/require"
)

const TestPluginServerEnv = "BAO_TEST_PLUGIN_SERVER"

// TestPluginServer is not an actual test but a hack to reuse the test binary
// as a plugin binary that is called into by the same test binary from the main
// test runner process.
func TestPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	gkwplugin.Serve(&gkwplugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			// We use the static wrapper as the wrapper to test with as it does
			// not require making any external infrastructure available.
			return static.NewWrapper()
		},
	})
}

// testBinaryHash returns the SHA-256 hash of the executing test binary.
func testBinaryHash(t *testing.T) string {
	hash, err := osutil.FileSha256Sum(os.Args[0])
	require.NoError(t, err)
	return hash
}

// testPluginConfig returns a plugin config for [TestPluginServer].
func testPluginConfig(t *testing.T) *server.PluginConfig {
	return &server.PluginConfig{
		Type:      consts.PluginTypeKMS.String(),
		Name:      "static",
		Command:   filepath.Base(os.Args[0]),
		Env:       []string{TestPluginServerEnv + "=1"},
		Args:      []string{"-test.run=TestPluginServer"},
		SHA256Sum: testBinaryHash(t),
	}
}

// TestGetClient tests plugin client creation, refcounting and shutdown.
func TestGetClient(t *testing.T) {
	logger := hclog.Default()
	catalog, err := NewCatalog(
		logger,
		&server.Config{
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins: []*server.PluginConfig{
				testPluginConfig(t),
				// This one should be ignored as it is a secrets engine plugin.
				{Type: consts.PluginTypeSecrets.String(), Name: "foo"},
			},
		},
		consts.PluginTypeKMS, gkwplugin.HandshakeConfig, gkwplugin.PluginSets,
	)
	require.NoError(t, err, "catalog should create successfully")
	require.Len(t, catalog.plugins, 1, "should have registered one plugin")
	require.Len(t, catalog.clients, 0, "should have no active plugin clients")

	_, ok, err := catalog.GetClient("foo")
	require.NoError(t, err, "should not error when requesting unknown plugin")
	require.False(t, ok, "should report that unknown plugin is not found")

	client1, ok, err := catalog.GetClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")
	require.NoError(t, client1.Ping(), "client should be reachable")
	require.Len(t, catalog.clients, 1, "should have one active plugin client")

	client2, ok, err := catalog.GetClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")
	require.NoError(t, client2.Ping(), "client should be reachable")
	require.Len(t, catalog.clients, 1, "should have one active plugin client")

	client1.Close()
	require.NoError(t, client2.Ping(), "client should still be reachable")
	require.Len(t, catalog.clients, 1, "should still have one active plugin client")

	client2.Close()
	require.Error(t, client2.Ping(), "client should not be reachable anymore")
	require.Len(t, catalog.clients, 0, "should have no more active plugin clients")
}

// TestReloadClient tests client reloading.
func TestReloadClient(t *testing.T) {
	logger := hclog.Default()
	catalog, err := NewCatalog(
		logger, &server.Config{
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins:         []*server.PluginConfig{testPluginConfig(t)},
		},
		consts.PluginTypeKMS, gkwplugin.HandshakeConfig, gkwplugin.PluginSets,
	)
	require.NoError(t, err, "catalog should create successfully")

	client1, ok, err := catalog.GetClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")

	client2, ok, err := catalog.GetClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")

	client1.process.Kill()
	require.Error(t, client1.Ping(), "client should not be reachable after process kill")
	require.Error(t, client2.Ping(), "client should not be reachable after process kill")

	client1, err = catalog.reloadClient(client1)
	require.NoError(t, err, "reload should succeed")
	require.NoError(t, client1.Ping(), "reloaded client should be reachable again")

	// Note: After reloading client2, we expect client1 to keep working
	// as reloading client2 should only catch it up with client1's already
	// performed reload.
	client2, err = catalog.reloadClient(client2)
	require.NoError(t, err, "reload should work")
	require.NoError(t, client2.Ping(), "reloaded client should work")
	require.NoError(t, client1.Ping(), "previously reloaded client should still work")
	require.True(t, client1 == client2, "second reload should yield same client")
}

// TestBadClientConfig tests several bad client configurations that lead to
// failure at client startup.
func TestBadClientConfig(t *testing.T) {
	logger := hclog.Default()
	tests := map[string]*server.Config{
		"NoPluginDirectory": {
			Plugins: []*server.PluginConfig{testPluginConfig(t)},
		},
		"BadPluginDirectory": {
			PluginDirectory: t.TempDir(),
			Plugins:         []*server.PluginConfig{testPluginConfig(t)},
		},
		"NoChecksum": {
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins: []*server.PluginConfig{func() *server.PluginConfig {
				config := testPluginConfig(t)
				config.SHA256Sum = ""
				return config
			}()},
		},
		"BadChecksum": {
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins: []*server.PluginConfig{func() *server.PluginConfig {
				config := testPluginConfig(t)
				config.SHA256Sum = config.SHA256Sum[1:] + "0"
				return config
			}()},
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			catalog, err := NewCatalog(logger, config, consts.PluginTypeKMS, gkwplugin.HandshakeConfig, gkwplugin.PluginSets)
			require.NoError(t, err, "catalog should create successfully")

			client, ok, err := catalog.GetClient("static")
			require.Error(t, err, "client should not instantiate")
			require.True(t, ok, "should report that known plugin exists")
			require.Nil(t, client, "should not return a client")
		})
	}
}
