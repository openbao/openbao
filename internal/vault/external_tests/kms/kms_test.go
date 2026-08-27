// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	transitKMS "github.com/openbao/go-kms-wrapping/kms/transit/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	"github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/kmsplugin"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"

	"github.com/stretchr/testify/require"
)

const TestPluginServerEnv = "BAO_TEST_PLUGIN_SERVER"

// TestTransitPluginServer runs a plugin that serves the Transit KMS.
func TestTransitPluginServer(t *testing.T) {
	if _, ok := os.LookupEnv(TestPluginServerEnv); !ok {
		t.Skip()
	}

	plugin.Serve(&plugin.ServeOpts{
		KMSFactoryFunc: transitKMS.New,
		Metadata: plugin.Metadata{
			SensitiveKMSFields: transitKMS.SensitiveKMSFields,
		},
	})
}

func TransitPluginConfig(t *testing.T) *server.PluginConfig {
	contents, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)

	checksum := sha256.Sum256(contents)

	return &server.PluginConfig{
		Name:      "external-transit",
		Type:      "kms",
		Command:   filepath.Base(os.Args[0]),
		Env:       []string{"BAO_TEST_PLUGIN_SERVER=true"},
		Args:      []string{"-test.run=TestTransitPluginServer"},
		SHA256Sum: hex.EncodeToString(checksum[:]),
	}
}

func TestKMS_BuiltinTransit(t *testing.T) {
	t.Parallel()

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
			"pki":     pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Create Transit mount for backend keys.
	err := client.Sys().Mount("keys", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)

	// Reference it from external keys API.
	_, err = client.Logical().Write("sys/external-keys/configs/kms", map[string]any{
		"plugin":            "transit",
		"address":           client.Address(),
		"mount_path":        "keys",
		"token":             client.Token(),
		"tls_ca_cert_bytes": string(cluster.CACertPEM),
	})
	require.NoError(t, err)
	ExerciseTransitKMS(t, client)
}

func TestKMS_ExternalTransit(t *testing.T) {
	t.Parallel()

	logger := hclog.Default()
	logger.SetLevel(hclog.Trace)

	catalog, err := kmsplugin.NewCatalog(logger, &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins: []*server.PluginConfig{
			TransitPluginConfig(t),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, catalog)

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
			"pki":     pki.Factory,
		},
		KMSPluginCatalog: catalog,
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core

	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Create Transit mount for backend keys.
	err = client.Sys().Mount("keys", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)

	// Reference it from external keys API.
	_, err = client.Logical().Write("sys/external-keys/configs/kms", map[string]any{
		"plugin":            "external-transit",
		"address":           client.Address(),
		"mount_path":        "keys",
		"token":             client.Token(),
		"tls_ca_cert_bytes": string(cluster.CACertPEM),
	})
	require.NoError(t, err)
	ExerciseTransitKMS(t, client)
}
