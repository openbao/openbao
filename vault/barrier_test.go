// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testBarrier(t *testing.T, b SecurityBarrier) {
	err, e, key := testInitAndUnseal(t, b)
	require.NoError(t, err)

	// Operations should work
	out, err := b.Get(context.Background(), "test")
	require.NoError(t, err)
	require.Nil(t, out)

	// List should have only "core/"
	keys, err := b.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "core/", keys[0])

	// Try to write
	err = b.Put(context.Background(), e)
	require.NoError(t, err)

	// Should be equal
	out, err = b.Get(context.Background(), "test")
	require.NoError(t, err)
	require.Equal(t, e, out)

	// List should show the items
	keys, err = b.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Equal(t, "core/", keys[0])
	require.Equal(t, "test", keys[1])

	// Delete should clear
	err = b.Delete(context.Background(), "test")
	require.NoError(t, err)

	// Double Delete is fine
	err = b.Delete(context.Background(), "test")
	require.NoError(t, err)

	// Should be nil
	out, err = b.Get(context.Background(), "test")
	require.NoError(t, err)
	require.Nil(t, out)

	// List should have nothing
	keys, err = b.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "core/", keys[0])

	// Add the item back
	err = b.Put(context.Background(), e)
	require.NoError(t, err)

	// Reseal should prevent any updates
	if err := b.Seal(); err != nil {
		t.Fatalf("err: %v", err)
	}

	// No access allowed
	_, err = b.Get(context.Background(), "test")
	require.ErrorIs(t, err, ErrBarrierSealed)

	// Unseal should work
	err = b.Unseal(context.Background(), key)
	require.NoError(t, err)

	// Should be equal
	out, err = b.Get(context.Background(), "test")
	require.NoError(t, err)
	require.Equal(t, e, out)

	// Final cleanup
	err = b.Delete(context.Background(), "test")
	require.NoError(t, err)

	// Reseal should prevent any updates
	err = b.Seal()
	require.NoError(t, err)

	// Modify the key
	key[0]++

	// Unseal should fail
	err = b.Unseal(context.Background(), key)
	require.ErrorIs(t, err, ErrBarrierInvalidKey)
}

func testInitAndUnseal(t *testing.T, b SecurityBarrier) (error, *logical.StorageEntry, []byte) {
	// Should not be initialized
	init, err := b.Initialized(context.Background())
	require.NoError(t, err)
	require.False(t, init, "should not be initialized")

	// Should start sealed
	sealed := b.Sealed()
	require.True(t, sealed, "should be sealed")

	// Sealing should be a no-op
	err = b.Seal()
	require.NoError(t, err)

	// All operations should fail
	e := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err = b.Put(context.Background(), e)
	require.ErrorIs(t, err, ErrBarrierSealed)
	_, err = b.Get(context.Background(), "test")
	require.ErrorIs(t, err, ErrBarrierSealed)
	err = b.Delete(context.Background(), "test")
	require.ErrorIs(t, err, ErrBarrierSealed)
	_, err = b.List(context.Background(), "")
	require.ErrorIs(t, err, ErrBarrierSealed)

	// Get a new key
	key, err := b.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Validate minimum key length
	min, max := b.KeyLength()
	require.GreaterOrEqual(t, min, 16, "minimum key size too small: %d", min)
	require.GreaterOrEqual(t, max, min, "maximum key size smaller than min")

	// Unseal should not work
	err = b.Unseal(context.Background(), key)
	require.ErrorIs(t, err, ErrBarrierNotInit)

	// Initialize the vault
	err = b.Initialize(context.Background(), key, nil, rand.Reader)
	require.NoError(t, err)

	// Double Initialize should fail
	err = b.Initialize(context.Background(), key, nil, rand.Reader)
	require.ErrorIs(t, err, ErrBarrierAlreadyInit)

	// Should be initialized
	init, err = b.Initialized(context.Background())
	require.NoError(t, err)
	require.True(t, init, "should be initialized")

	// Should still be sealed
	sealed = b.Sealed()
	require.True(t, sealed, "should be sealed")

	// Unseal should work
	err = b.Unseal(context.Background(), key)
	require.NoError(t, err)

	// Unseal should no-op when done twice
	err = b.Unseal(context.Background(), key)
	require.NoError(t, err)

	// Should no longer be sealed
	sealed = b.Sealed()
	require.False(t, sealed, "should be unsealed")

	// Verify the root key
	err = b.VerifyRoot(key)
	require.NoError(t, err)
	return err, e, key
}

func testBarrier_Rotate(t *testing.T, b SecurityBarrier) {
	// Initialize the barrier
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	err := b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the key info
	info, err := b.ActiveKeyInfo()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if info.Term != 1 {
		t.Fatalf("Bad term: %d", info.Term)
	}
	if time.Since(info.InstallTime) > time.Second {
		t.Fatalf("Bad install: %v", info.InstallTime)
	}
	first := info.InstallTime

	// Write a key
	e1 := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := b.Put(context.Background(), e1); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Rotate the encryption key
	newTerm, err := b.Rotate(context.Background(), rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if newTerm != 2 {
		t.Fatalf("bad: %v", newTerm)
	}

	// Check the key info
	info, err = b.ActiveKeyInfo()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if info.Term != 2 {
		t.Fatalf("Bad term: %d", info.Term)
	}
	if !info.InstallTime.After(first) {
		t.Fatalf("Bad install: %v", info.InstallTime)
	}

	// Write another key
	e2 := &logical.StorageEntry{Key: "foo", Value: []byte("test")}
	if err := b.Put(context.Background(), e2); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reading both should work
	out, err := b.Get(context.Background(), e1.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	out, err = b.Get(context.Background(), e2.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	// Seal and unseal
	err = b.Seal()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reading both should work
	out, err = b.Get(context.Background(), e1.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	out, err = b.Get(context.Background(), e2.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	// Should be fine to reload keyring
	err = b.ReloadKeyring(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func testBarrier_RotateRootKey(t *testing.T, b SecurityBarrier) {
	// Initialize the barrier
	key, _ := b.GenerateKey(rand.Reader)
	b.Initialize(context.Background(), key, nil, rand.Reader)
	err := b.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Write a key
	e1 := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := b.Put(context.Background(), e1); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify the root key
	if err := b.VerifyRoot(key); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Rotate to a new root key
	newKey, _ := b.GenerateKey(rand.Reader)
	err = b.RotateRootKey(context.Background(), newKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify the old root key
	if err := b.VerifyRoot(key); err != ErrBarrierInvalidKey {
		t.Fatalf("err: %v", err)
	}

	// Verify the new root key
	if err := b.VerifyRoot(newKey); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reading should work
	out, err := b.Get(context.Background(), e1.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	// Seal
	err = b.Seal()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Unseal with old key should fail
	err = b.Unseal(context.Background(), key)
	if err == nil {
		t.Fatal("unseal should fail")
	}

	// Unseal with new keys should work
	err = b.Unseal(context.Background(), newKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reading should work
	out, err = b.Get(context.Background(), e1.Key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatalf("bad: %v", out)
	}

	// Should be fine to reload keyring
	err = b.ReloadKeyring(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func testBarrier_Upgrade(t *testing.T, b1, b2 SecurityBarrier) {
	// Initialize the barrier
	key, _ := b1.GenerateKey(rand.Reader)
	b1.Initialize(context.Background(), key, nil, rand.Reader)
	err := b1.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b2.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Rotate the encryption key
	newTerm, err := b1.Rotate(context.Background(), rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Create upgrade path
	err = b1.CreateUpgrade(context.Background(), newTerm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check for an upgrade
	did, updated, err := b2.CheckUpgrade(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !did || updated != newTerm {
		t.Fatal("failed to upgrade")
	}

	// Should have no upgrades pending
	did, updated, err = b2.CheckUpgrade(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if did {
		t.Fatal("should not have upgrade")
	}
	require.EqualValues(t, 0, updated)

	// Rotate the encryption key
	newTerm, err = b1.Rotate(context.Background(), rand.Reader)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Create upgrade path
	err = b1.CreateUpgrade(context.Background(), newTerm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Destroy upgrade path
	err = b1.DestroyUpgrade(context.Background(), newTerm)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should have no upgrades pending
	did, updated, err = b2.CheckUpgrade(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if did {
		t.Fatal("should not have upgrade")
	}
	require.EqualValues(t, 0, updated)
}

func testBarrier_Upgrade_RotateRootKey(t *testing.T, b1, b2 SecurityBarrier) {
	// Initialize the barrier
	key, _ := b1.GenerateKey(rand.Reader)
	b1.Initialize(context.Background(), key, nil, rand.Reader)
	err := b1.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	err = b2.Unseal(context.Background(), key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Rotate to a new root key
	newKey, _ := b1.GenerateKey(rand.Reader)
	err = b1.RotateRootKey(context.Background(), newKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reload the root key
	err = b2.ReloadRootKey(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Reload the keyring
	err = b2.ReloadKeyring(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}
