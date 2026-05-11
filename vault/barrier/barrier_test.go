// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package barrier

import (
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testBarrier(t *testing.T, b SecurityBarrier) {
	ctx := t.Context()

	var prefix string
	switch cb := b.(type) {
	case *AESGCMBarrier:
		prefix = cb.metaPrefix
	case *TransactionalAESGCMBarrier:
		prefix = cb.metaPrefix
	}

	e, key := testInitAndUnseal(t, b)

	// Operations should work
	out, err := b.Get(ctx, prefix+"test")
	require.NoError(t, err)
	require.Nil(t, out)

	// List should have only "core/"
	keys, err := b.List(ctx, prefix)
	require.NoError(t, err)
	require.Equal(t, []string{"core/"}, keys)

	// Try to write
	require.NoError(t, b.Put(ctx, e))

	// Should be equal
	out, err = b.Get(ctx, prefix+"test")
	require.NoError(t, err)
	require.Equal(t, e, out)

	// List should show the items
	keys, err = b.List(ctx, prefix)
	require.NoError(t, err)
	require.Equal(t, []string{"core/", "test"}, keys)

	// Delete should clear
	require.NoError(t, b.Delete(ctx, prefix+"test"))

	// Double Delete is fine
	require.NoError(t, b.Delete(ctx, prefix+"test"))

	// Should be nil
	out, err = b.Get(ctx, prefix+"test")
	require.NoError(t, err)
	require.Nil(t, out)

	// List should have nothing
	keys, err = b.List(ctx, prefix)
	require.NoError(t, err)
	require.Equal(t, []string{"core/"}, keys)

	// Add the item back
	require.NoError(t, b.Put(ctx, e))

	// Reseal should prevent any updates
	require.NoError(t, b.Seal())

	// No access allowed
	_, err = b.Get(ctx, prefix+"test")
	require.ErrorIs(t, err, ErrBarrierSealed)

	// Unseal should work
	require.NoError(t, b.Unseal(ctx, key))

	// Should be equal
	out, err = b.Get(ctx, prefix+"test")
	require.NoError(t, err)
	require.Equal(t, e, out)

	// Final cleanup
	require.NoError(t, b.Delete(ctx, prefix+"test"))

	// Reseal should prevent any updates
	require.NoError(t, b.Seal())

	// Modify the key
	key[0]++

	// Unseal should fail
	require.ErrorIs(t, b.Unseal(ctx, key), ErrBarrierInvalidKey)
}

func testInitAndUnseal(t *testing.T, b SecurityBarrier) (*logical.StorageEntry, []byte) {
	ctx := t.Context()

	var prefix string
	switch cb := b.(type) {
	case *AESGCMBarrier:
		prefix = cb.metaPrefix
	case *TransactionalAESGCMBarrier:
		prefix = cb.metaPrefix
	}

	// Should not be initialized
	init, err := b.Initialized(ctx)
	require.NoError(t, err)
	require.False(t, init, "should not be initialized")

	// Should start sealed
	require.True(t, b.Sealed(), "should be sealed")

	// Sealing should be a no-op
	require.NoError(t, b.Seal())

	// All operations should fail
	e := &logical.StorageEntry{Key: prefix + "test", Value: []byte("test")}
	require.ErrorIs(t, b.Put(ctx, e), ErrBarrierSealed)
	_, err = b.Get(ctx, prefix+"test")
	require.ErrorIs(t, err, ErrBarrierSealed)
	require.ErrorIs(t, b.Delete(ctx, prefix+"test"), ErrBarrierSealed)
	_, err = b.List(ctx, prefix)
	require.ErrorIs(t, err, ErrBarrierSealed)

	// Get a new key
	key, err := b.GenerateKey()
	require.NoError(t, err)

	// Validate minimum key length
	min, max := b.KeyLength()
	require.GreaterOrEqual(t, min, 16, "minimum key size too small")
	require.GreaterOrEqual(t, max, min, "maximum key size smaller than min")

	// Unseal should not work
	require.ErrorIs(t, b.Unseal(ctx, key), ErrBarrierNotInit)

	// Initialize the vault
	require.NoError(t, b.Initialize(ctx, key, nil))

	// Double Initialize should fail
	require.ErrorIs(t, b.Initialize(ctx, key, nil), ErrBarrierAlreadyInit)

	// Should be initialized
	init, err = b.Initialized(ctx)
	require.NoError(t, err)
	require.True(t, init)

	// Should still be sealed
	require.True(t, b.Sealed())

	// Unseal should work
	require.NoError(t, b.Unseal(ctx, key))

	// Unseal should no-op when done twice
	require.NoError(t, b.Unseal(ctx, key))

	// Should no longer be sealed
	require.False(t, b.Sealed())

	// Verify the root key
	require.NoError(t, b.VerifyRoot(key))

	return e, key
}

func testBarrier_Rotate(t *testing.T, b SecurityBarrier) {
	ctx := t.Context()

	// Initialize the barrier
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Check the key info
	info, err := b.ActiveKeyInfo()
	require.NoError(t, err)
	require.Equal(t, 1, info.Term)
	require.False(t, time.Since(info.InstallTime) > time.Second)
	first := info.InstallTime

	// Write a key
	e1 := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, e1))

	// Rotate the encryption key
	newTerm, err := b.Rotate(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, newTerm)

	// Check the key info
	info, err = b.ActiveKeyInfo()
	require.NoError(t, err)
	require.True(t, info.InstallTime.After(first))

	// Write another key
	e2 := &logical.StorageEntry{Key: "foo", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, e2))

	// Reading both should work
	out, err := b.Get(ctx, e1.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	out, err = b.Get(ctx, e2.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Seal and unseal
	require.NoError(t, b.Seal())
	require.NoError(t, b.Unseal(ctx, key))

	// Reading both should work
	out, err = b.Get(ctx, e1.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	out, err = b.Get(ctx, e2.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Should be fine to reload keyring
	require.NoError(t, b.ReloadKeyring(ctx))
}

func testBarrier_RotateRootKey(t *testing.T, b SecurityBarrier) {
	ctx := t.Context()

	// Initialize the barrier
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Write a key
	e1 := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, e1))

	// Verify the root key
	require.NoError(t, b.VerifyRoot(key))

	// Rotate to a new root key
	newKey, _ := b.GenerateKey()
	require.NoError(t, b.RotateRootKey(ctx, newKey))

	// Verify the old root key
	require.ErrorIs(t, b.VerifyRoot(key), ErrBarrierInvalidKey)

	// Verify the new root key
	require.NoError(t, b.VerifyRoot(newKey))

	// Reading should work
	out, err := b.Get(ctx, e1.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Seal
	require.NoError(t, b.Seal())

	// Unseal with old key should fail
	require.Error(t, b.Unseal(ctx, key))

	// Unseal with new keys should work
	require.NoError(t, b.Unseal(ctx, newKey))

	// Reading should work
	out, err = b.Get(ctx, e1.Key)
	require.NoError(t, err)
	require.NotNil(t, out)

	// Should be fine to reload keyring
	require.NoError(t, b.ReloadKeyring(ctx))
}

func testBarrier_Upgrade(t *testing.T, b1, b2 SecurityBarrier) {
	ctx := t.Context()

	// Initialize the barrier
	key, _ := b1.GenerateKey()
	require.NoError(t, b1.Initialize(ctx, key, nil))
	require.NoError(t, b1.Unseal(ctx, key))
	require.NoError(t, b2.Unseal(ctx, key))

	// Rotate the encryption key
	newTerm, err := b1.Rotate(ctx)
	require.NoError(t, err)
	// Create upgrade path
	require.NoError(t, b1.CreateUpgrade(ctx, newTerm))

	// Check for an upgrade
	did, updated, err := b2.CheckUpgrade(ctx)
	require.NoError(t, err)
	require.True(t, did, "failed to upgrade")
	require.True(t, updated == newTerm, "failed to upgrade")

	// Should have no upgrades pending
	did, updated, err = b2.CheckUpgrade(ctx)
	require.NoError(t, err)
	require.False(t, did, "should not have upgrade")
	require.EqualValues(t, 0, updated)

	// Rotate the encryption key
	newTerm, err = b1.Rotate(ctx)
	require.NoError(t, err)

	// Create upgrade path
	require.NoError(t, b1.CreateUpgrade(ctx, newTerm))
	// Destroy upgrade path
	require.NoError(t, b1.DestroyUpgrade(ctx, newTerm))

	// Should have no upgrades pending
	did, updated, err = b2.CheckUpgrade(ctx)
	require.NoError(t, err)
	require.False(t, did, "should not have upgrade")
	require.EqualValues(t, 0, updated)
}

func testBarrier_Upgrade_RotateRootKey(t *testing.T, b1, b2 SecurityBarrier) {
	ctx := t.Context()

	// Initialize the barrier
	key, _ := b1.GenerateKey()
	require.NoError(t, b1.Initialize(ctx, key, nil))
	require.NoError(t, b1.Unseal(ctx, key))
	require.NoError(t, b2.Unseal(ctx, key))

	// Rotate to a new root key
	newKey, _ := b1.GenerateKey()
	require.NoError(t, b1.RotateRootKey(ctx, newKey))

	// Reload the root key
	require.NoError(t, b2.ReloadRootKey(ctx))

	// Reload the keyring
	require.NoError(t, b2.ReloadKeyring(ctx))
}
