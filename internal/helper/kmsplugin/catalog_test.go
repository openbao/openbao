// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/kms/transit/v2"
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/osutil"
	"github.com/stretchr/testify/require"
)

const TestPluginServerEnv = "BAO_TEST_PLUGIN_SERVER"

// TestStaticPluginServer runs a plugin that serves the static wrapper.
func TestStaticPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	gkwplugin.Serve(&gkwplugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return static.NewWrapper()
		},
	})
}

// TestTransitPluginServer runs a plugin that serves the Transit KMS.
func TestTransitPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	gkwplugin.Serve(&gkwplugin.ServeOpts{
		KMSFactoryFunc: transit.New,
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

// TestGetClient tests plugin client creation, refcounting and shutdown.
func TestGetClient(t *testing.T) {
	logger := hclog.Default()
	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins: []*server.PluginConfig{
			StaticPluginConfig,
			// This one should be ignored as it is a secrets engine plugin.
			{Type: consts.PluginTypeSecrets.String(), Name: "foo"},
		},
	})
	require.NoError(t, err, "catalog should create successfully")
	require.Len(t, catalog.plugins, 1, "should have registered one plugin")
	require.Len(t, catalog.clients, 0, "should have no active plugin clients")

	_, ok, err := catalog.getClient("foo")
	require.NoError(t, err, "should not error when requesting unknown plugin")
	require.False(t, ok, "should report that unknown plugin is not found")

	client1, ok, err := catalog.getClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")
	require.NoError(t, client1.Ping(), "client should be reachable")
	require.Len(t, catalog.clients, 1, "should have one active plugin client")

	client2, ok, err := catalog.getClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")
	require.NoError(t, client2.Ping(), "client should be reachable")
	require.Len(t, catalog.clients, 1, "should have one active plugin client")

	client1.close()
	require.NoError(t, client2.Ping(), "client should still be reachable")
	require.Len(t, catalog.clients, 1, "should still have one active plugin client")

	client2.close()
	require.Error(t, client2.Ping(), "client should not be reachable anymore")
	require.Len(t, catalog.clients, 0, "should have no more active plugin clients")
}

// TestReloadClient tests client reloading.
func TestReloadClient(t *testing.T) {
	logger := hclog.Default()
	catalog, err := NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{StaticPluginConfig},
	})
	require.NoError(t, err, "catalog should create successfully")

	client1, ok, err := catalog.getClient("static")
	require.NoError(t, err, "should instantiate client for known plugin")
	require.True(t, ok, "should report that known plugin exists")

	client2, ok, err := catalog.getClient("static")
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
			Plugins: []*server.PluginConfig{StaticPluginConfig},
		},
		"BadPluginDirectory": {
			PluginDirectory: t.TempDir(),
			Plugins:         []*server.PluginConfig{StaticPluginConfig},
		},
		"NoChecksum": {
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins: []*server.PluginConfig{{
				Type:    StaticPluginConfig.Type,
				Name:    StaticPluginConfig.Name,
				Command: StaticPluginConfig.Command,
				Args:    StaticPluginConfig.Args,
				Env:     StaticPluginConfig.Env,
			}},
		},
		"BadChecksum": {
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins: []*server.PluginConfig{{
				Type:      StaticPluginConfig.Type,
				Name:      StaticPluginConfig.Name,
				Command:   StaticPluginConfig.Command,
				Args:      StaticPluginConfig.Args,
				Env:       StaticPluginConfig.Env,
				SHA256Sum: StaticPluginConfig.SHA256Sum[:1] + "0",
			}},
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			catalog, err := NewCatalog(logger, config)
			require.NoError(t, err, "catalog should create successfully")

			client, ok, err := catalog.getClient("static")
			require.Error(t, err, "client should not instantiate")
			require.True(t, ok, "should report that known plugin exists")
			require.Nil(t, client, "should not return a client")
		})
	}
}
