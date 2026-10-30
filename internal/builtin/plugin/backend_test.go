// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin_test

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	logicalPlugin "github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/openbao/sdk/v2/plugin/mock"
	"github.com/openbao/openbao/v2/internal/builtin/plugin"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestBackend(t *testing.T) {
	pluginCmds := []string{"TestBackend_PluginMain", "TestBackend_PluginMain_Multiplexed"}

	for _, pluginCmd := range pluginCmds {
		t.Run(pluginCmd, func(t *testing.T) {
			config, cleanup := testConfig(t, pluginCmd)
			defer cleanup()

			_, err := plugin.Backend(t.Context(), config)
			require.NoError(t, err)
		})
	}
}

func TestBackend_Factory(t *testing.T) {
	pluginCmds := []string{"TestBackend_PluginMain", "TestBackend_PluginMain_Multiplexed"}

	for _, pluginCmd := range pluginCmds {
		t.Run(pluginCmd, func(t *testing.T) {
			config, cleanup := testConfig(t, pluginCmd)
			defer cleanup()

			_, err := plugin.Factory(t.Context(), config)
			require.NoError(t, err)
		})
	}
}

func TestBackend_PluginMain(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}

	err := logicalPlugin.Serve(&logicalPlugin.ServeOpts{
		BackendFactoryFunc: mock.Factory,
	})
	require.NoError(t, err)
}

func TestBackend_PluginMain_Multiplexed(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}

	err := logicalPlugin.ServeMultiplex(&logicalPlugin.ServeOpts{
		BackendFactoryFunc: mock.Factory,
	})
	require.NoError(t, err)
}

func testConfig(t *testing.T, pluginCmd string) (*logical.BackendConfig, func()) {
	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	cores := cluster.Cores

	core := cores[0]

	sys := vault.TestDynamicSystemView(core.Core, nil)

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Debug),
		System: sys,
		Config: map[string]string{
			"plugin_name":    "mock-plugin",
			"plugin_type":    "secret",
			"plugin_version": "v0.0.0+mock",
		},
	}

	vault.TestAddTestPlugin(t, core.Core, "mock-plugin", consts.PluginTypeSecrets, "", pluginCmd, []string{}, "")

	return config, func() {
		cluster.Cleanup()
	}
}
