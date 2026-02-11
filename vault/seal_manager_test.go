// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/stretchr/testify/require"
)

func TestSealManager_Reset(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	// TODO(wslabosz): with seal manager running on unseal,
	// no need to do it manually
	c.SetupSealManager()

	// verify initial state of seal manager
	require.Len(t, c.sealManager.barrierByNamespace.ToMap(), 1)
	require.Len(t, c.sealManager.sealByNamespace, 1)
	require.Len(t, c.sealManager.unlockInformationByNamespace, 1)
	require.Len(t, c.sealManager.rotationConfigByNamespace, 1)

	sealConfig := &SealConfig{
		Type:            "shamir",
		SecretShares:    1,
		SecretThreshold: 1,
	}

	for i := range 10 {
		err := c.sealManager.SetSeal(namespace.RootContext(t.Context()), sealConfig, &namespace.Namespace{UUID: strconv.Itoa(i), Path: fmt.Sprintf("test%d/", i)}, false)
		require.NoError(t, err)
	}
	require.Len(t, c.sealManager.barrierByNamespace.ToMap(), 11)
	require.Len(t, c.sealManager.sealByNamespace, 11)
	require.Len(t, c.sealManager.unlockInformationByNamespace, 11)
	require.Len(t, c.sealManager.rotationConfigByNamespace, 11)

	c.sealManager.Reset()

	require.Len(t, c.sealManager.barrierByNamespace.ToMap(), 1)
	require.Len(t, c.sealManager.sealByNamespace, 1)
	require.Len(t, c.sealManager.unlockInformationByNamespace, 1)
	require.Len(t, c.sealManager.rotationConfigByNamespace, 1)
}

func TestSealManager_SetSeal(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	// TODO(wslabosz): with seal manager running on unseal,
	// no need to do it manually
	c.SetupSealManager()
	ctx := namespace.RootContext(t.Context())

	tc := []struct {
		name           string
		config         *SealConfig
		ns             *namespace.Namespace
		writeToStorage bool
		wantErr        error
	}{
		{
			name: "happy path",
			config: &SealConfig{
				Type:            "shamir",
				SecretShares:    1,
				SecretThreshold: 1,
			},
			ns: testCreateNamespace(t, ctx, c.systemBackend, "test", nil),
		},
		{
			name: "happy path, config saved to storage",
			config: &SealConfig{
				Type:            "shamir",
				SecretShares:    1,
				SecretThreshold: 1,
			},
			ns:             testCreateNamespace(t, ctx, c.systemBackend, "test2", nil),
			writeToStorage: true,
		},
		{
			name: "validation failure",
			config: &SealConfig{
				Type:            "shamir",
				SecretShares:    1,
				SecretThreshold: 3,
			},
			ns:      testCreateNamespace(t, ctx, c.systemBackend, "test3", nil),
			wantErr: errors.New("invalid seal configuration"),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := c.sealManager.SetSeal(ctx, tt.config, tt.ns, tt.writeToStorage)
			if err != nil {
				require.Error(t, tt.wantErr, err.Error())
				return
			}

			seal := c.sealManager.NamespaceSeal(tt.ns.UUID)
			require.NotEmpty(t, seal)

			require.NotEmpty(t, c.sealManager.NamespaceBarrier(tt.ns.Path))
			require.NotEmpty(t, c.sealManager.NamespaceSeal(tt.ns.UUID))
			require.NotNil(t, c.sealManager.NamespaceUnlockInformation(tt.ns.UUID))
			require.NotNil(t, c.sealManager.NamespaceRotationConfig(tt.ns.UUID))

			// verify storage
			cfg, err := seal.BarrierConfig(ctx)
			require.NoError(t, err)
			if tt.writeToStorage {
				require.Equal(t, tt.config, cfg)
			} else {
				require.Empty(t, cfg)
			}

			c.sealManager.RemoveNamespace(tt.ns)

			require.Empty(t, c.sealManager.NamespaceBarrier(tt.ns.Path))
			require.Empty(t, c.sealManager.NamespaceSeal(tt.ns.UUID))
			require.Nil(t, c.sealManager.NamespaceUnlockInformation(tt.ns.UUID))
			require.Nil(t, c.sealManager.NamespaceRotationConfig(tt.ns.UUID))
		})
	}
}

func TestSealManager_InitializeBarrier(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	// TODO(wslabosz): with seal manager running on unseal,
	// no need to do it manually
	c.SetupSealManager()
	ctx := namespace.RootContext(t.Context())

	flawedNS := &namespace.Namespace{UUID: "notpresent", Path: "flawed/"}
	// naive checking for seal & barrier in mem presence
	// in real scenario if one exists the other also has to exist
	_, err := c.sealManager.InitializeBarrier(ctx, flawedNS)
	require.ErrorIs(t, err, ErrNotSealable)

	tSeal := &defaultSeal{core: c}
	tSeal.SetConfigAccess(c.barrier)

	c.sealManager.sealByNamespace["notpresent"] = tSeal
	_, err = c.sealManager.InitializeBarrier(ctx, flawedNS)
	require.ErrorIs(t, err, ErrNotSealable)

	c.sealManager.barrierByNamespace.Insert(flawedNS.Path, barrier.NewAESGCMBarrier(c.physical, NamespaceStoragePathPrefix(flawedNS)))

	// check seal config presence in storage
	_, err = c.sealManager.InitializeBarrier(ctx, flawedNS)
	// dummy barrier is sealed
	require.ErrorContains(t, err, "failed to retrieve seal config")

	sealConfig := &SealConfig{
		Type:            "shamir",
		SecretShares:    3,
		SecretThreshold: 2,
	}
	ns := &namespace.Namespace{UUID: "ns1", Path: "test/"}
	err = c.sealManager.SetSeal(ctx, sealConfig, ns, true)
	require.NoError(t, err)

	// make secure random reader artificially fail
	c.secureRandomReader = io.LimitReader(c.secureRandomReader, 0)
	_, err = c.sealManager.InitializeBarrier(ctx, ns)
	require.ErrorContains(t, err, "failed to generate namespace seal key")

	// return to default reader
	c.secureRandomReader = rand.Reader

	keyShares, err := c.sealManager.InitializeBarrier(ctx, ns)
	require.NoError(t, err)
	require.NotEmpty(t, keyShares)

	// verify the barrier is unsealed
	b := c.sealManager.NamespaceBarrier(ns.Path)
	require.False(t, b.Sealed())

	// keyring is stored
	keyring, err := b.Keyring()
	require.NoError(t, err)
	require.NotNil(t, keyring)

	// stored keys are written
	seal := c.sealManager.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)
	storedKeys, err := seal.GetStoredKeys(namespace.ContextWithNamespace(ctx, ns))
	require.NoError(t, err)
	require.NotEmpty(t, storedKeys)
}

func TestSealManager_SealStatus(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	// TODO(wslabosz): with seal manager running on unseal,
	// no need to do it manually
	c.SetupSealManager()
	ctx := namespace.RootContext(t.Context())

	// check for seal existence
	sealStatus, err := c.sealManager.SealStatus(ctx, &namespace.Namespace{UUID: "notexisting/"})
	require.ErrorIs(t, err, ErrNotSealable)
	require.Nil(t, sealStatus)

	sealConfig := &SealConfig{
		Type:            "shamir",
		SecretShares:    3,
		SecretThreshold: 2,
	}
	ns := &namespace.Namespace{UUID: "failure", Path: "ns1/"}

	err = c.sealManager.SetSeal(ctx, sealConfig, ns, false)
	require.NoError(t, err)

	// barrier not yet initialized
	sealStatus, err = c.sealManager.SealStatus(ctx, ns)
	require.ErrorIs(t, err, barrier.ErrBarrierNotInit)
	require.Nil(t, sealStatus)

	// config has to be present in storage to init barrier
	_, err = c.sealManager.InitializeBarrier(ctx, ns)
	require.ErrorContains(t, err, "namespace barrier reports initialized but no seal configuration found")

	ns = &namespace.Namespace{UUID: "success", Path: "ns2/"}

	// save seal config to storage
	err = c.sealManager.SetSeal(ctx, sealConfig, ns, true)
	require.NoError(t, err)

	keyShares, err := c.sealManager.InitializeBarrier(ctx, ns)
	require.NoError(t, err)

	sealStatus, err = c.sealManager.SealStatus(ctx, ns)
	require.NoError(t, err)
	require.Equal(t, sealConfig.Type, sealStatus.Type)
	require.True(t, sealStatus.Initialized)
	require.False(t, sealStatus.RecoverySeal)
	require.False(t, sealStatus.Sealed)
	require.Equal(t, 3, sealStatus.N)
	require.Equal(t, 2, sealStatus.T)
	require.Equal(t, 0, sealStatus.Progress)
	require.Empty(t, sealStatus.Nonce)

	// verify update of unlock information
	new, err := c.sealManager.recordUnsealPart(ns, keyShares[0])
	require.True(t, new)
	require.NoError(t, err)

	sealStatus, err = c.sealManager.SealStatus(ctx, ns)
	require.NoError(t, err)
	require.Equal(t, 1, sealStatus.Progress)
}
