// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package router

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	"github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/vault/backend"
	"github.com/stretchr/testify/require"
)

func TestRouter_MountSubpath_Checks(t *testing.T) {
	testRouter_MountSubpath(t, []string{"a/abcd/123", "abcd/123"})
	testRouter_MountSubpath(t, []string{"abcd/123", "a/abcd/123"})
	testRouter_MountSubpath(t, []string{"a/abcd/123", "abcd/123"})
}

func testRouter_MountSubpath(t *testing.T, mountPoints []string) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	// Test auth
	authInput := &api.EnableAuthOptions{
		Type: "userpass",
	}
	for _, mp := range mountPoints {
		t.Logf("mounting %s", "auth/"+mp)
		err := client.Sys().EnableAuthWithOptions("auth/"+mp, authInput)
		require.NoError(t, err)
	}

	// Test secrets
	mountInput := &api.MountInput{
		Type: "pki",
	}
	for _, mp := range mountPoints {
		t.Logf("mounting %s", "s/"+mp)
		err := client.Sys().Mount("s/"+mp, mountInput)
		require.NoError(t, err)
	}

	cluster.EnsureCoresSealed(t)
	cluster.UnsealCores(t)
	t.Logf("Done: %#v", mountPoints)
}

func TestRouter_UnmountRollbackIsntFatal(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"noop": backend.NoopBackendRollbackErrFactory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	require.NoError(t, client.Sys().Mount("noop", &api.MountInput{
		Type: "noop",
	}), "failed to mount PKI")

	_, err := client.Logical().Write("sys/plugins/reload/backend", map[string]any{
		"mounts": "noop",
	})
	require.NoError(t, err, "expected reload of noop with broken periodic func to succeed; got")

	_, err = client.Logical().Write("sys/remount", map[string]any{
		"from": "noop",
		"to":   "noop-to",
	})
	require.NoError(t, err, "expected remount of noop with broken periodic func to succeed; got")

	cluster.EnsureCoresSealed(t)
	cluster.UnsealCores(t)
}
