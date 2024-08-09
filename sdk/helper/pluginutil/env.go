// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pluginutil

import (
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/openbao/openbao/api/v2"
)

const (
	// PluginAutoMTLSEnv is used to ensure AutoMTLS is used. This will override
	// setting a TLSProviderFunc for a plugin.
	PluginAutoMTLSEnv = "BAO_PLUGIN_AUTOMTLS_ENABLED"

	// PluginMlockEnabled is the ENV name used to pass the configuration for
	// enabling mlock
	PluginMlockEnabled = "BAO_PLUGIN_MLOCK_ENABLED"

	// PluginVaultVersionEnv is the ENV name used to pass the version of the
	// vault server to the plugin
	PluginVaultVersionEnv = "BAO_VERSION"

	// PluginMetadataModeEnv is an ENV name used to disable TLS communication
	// to bootstrap mounting plugins.
	PluginMetadataModeEnv = "BAO_PLUGIN_METADATA_MODE"

	// PluginUnwrapTokenEnv is the ENV name used to pass unwrap tokens to the
	// plugin.
	PluginUnwrapTokenEnv = "BAO_UNWRAP_TOKEN"

	// PluginCACertPEMEnv is an ENV name used for holding a CA PEM-encoded
	// string. Used for testing.
	PluginCACertPEMEnv = "BAO_TESTING_PLUGIN_CA_PEM"

	// PluginMultiplexingOptOut is an ENV name used to define a comma separated list of plugin names
	// opted-out of the multiplexing feature; for emergencies if multiplexing ever causes issues
	PluginMultiplexingOptOut = "BAO_PLUGIN_MULTIPLEXING_OPT_OUT"
)

// OptionallyEnableMlock determines if mlock should be called, and if so enables
// mlock.
func OptionallyEnableMlock() error {
	if api.ReadBaoVariable(PluginMlockEnabled) == "true" {
		return mlock.LockMemory()
	}

	return nil
}

// InMetadataMode returns true if the plugin calling this function is running in metadata mode.
func InMetadataMode() bool {
	return api.ReadBaoVariable(PluginMetadataModeEnv) == "true"
}
