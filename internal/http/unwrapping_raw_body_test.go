// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	kv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestUnwrapping_Raw_Body(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Mount a k/v backend, version 2
	err := client.Sys().Mount("kv", &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
	require.NoError(t, err)

	client.SetWrappingLookupFunc(func(operation, path string) string {
		return "5m"
	})
	secret, err := client.Logical().Write("kv/foo/bar", map[string]any{
		"a": "b",
	})
	require.NoError(t, err)
	if secret == nil {
		t.Fatal("nil secret")
	}
	if secret.WrapInfo == nil {
		t.Fatal("nil wrap info")
	}
	wrapToken := secret.WrapInfo.Token

	client.SetWrappingLookupFunc(nil)
	secret, err = client.Logical().Unwrap(wrapToken)
	require.NoError(t, err)
	if len(secret.Warnings) != 1 {
		t.Fatal("expected 1 warning")
	}
}
