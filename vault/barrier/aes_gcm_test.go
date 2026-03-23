// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package barrier

import (
	"bytes"
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

var logger = logging.NewVaultLogger(log.Trace)

func TestAESGCMBarrier_Basic(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	testBarrier(t, b)
}

func TestAESGCMBarrier_Rotate(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	testBarrier_Rotate(t, b)
}

func TestAESGCMBarrier_MissingRotateConfig(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Write a keyring which lacks rotation config settings
	oldKeyring := b.keyring.Clone()
	oldKeyring.rotationConfig = KeyRotationConfig{}
	require.NoError(t, b.persistKeyring(ctx, oldKeyring))
	require.NoError(t, b.ReloadKeyring(ctx))

	require.True(t, defaultRotationConfig.Equals(b.keyring.rotationConfig),
		"expected empty rotation config to recover as default config")
}

func TestAESGCMBarrier_Upgrade(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b1 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b2 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	testBarrier_Upgrade(t, b1, b2)
}

func TestAESGCMBarrier_Upgrade_RotateRootKey(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b1 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b2 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	testBarrier_Upgrade_RotateRootKey(t, b1, b2)

	// Test migration from legacy to new root key path. Move the existing
	// root key over to the legacy path.
	entry, err := b1.Get(ctx, RootKeyPath)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, entry.Key, RootKeyPath)

	entry.Key = LegacyRootKeyPath
	require.NoError(t, b1.Put(ctx, entry))
	require.NoError(t, b1.Delete(ctx, RootKeyPath))

	// Now reload b1; this should succeed but not migrate the key.
	require.NoError(t, b1.ReloadRootKey(ctx))

	oldEntry, err := b1.Get(ctx, LegacyRootKeyPath)
	require.NoError(t, err)
	require.NotNil(t, oldEntry)
	require.Equal(t, entry.Value, oldEntry.Value)

	newEntry, err := b1.Get(ctx, RootKeyPath)
	require.NoError(t, err)
	require.Nil(t, newEntry)

	// Now persist b1; this should remove the legacy key path.
	require.NoError(t, b1.persistKeyring(ctx, b1.keyring))

	oldEntry, err = b1.Get(ctx, LegacyRootKeyPath)
	require.NoError(t, err)
	require.Nil(t, oldEntry)

	newEntry, err = b1.Get(ctx, RootKeyPath)
	require.NoError(t, err)
	require.NotNil(t, newEntry)
	require.Equal(t, entry.Value, newEntry.Value)
}

func TestAESGCMBarrier_RotateRootKey(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	testBarrier_RotateRootKey(t, b)
}

// Verify data sent through is encrypted
func TestAESGCMBarrier_Confidential(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, entry))

	// Check the physical entry
	pe, err := inm.Get(ctx, "test")
	require.NoError(t, err)
	require.NotNil(t, pe)
	require.Equal(t, "test", pe.Key)
	require.False(t, bytes.Equal(pe.Value, entry.Value))
}

// Verify data sent through cannot be tampered with
func TestAESGCMBarrier_Integrity(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, entry))

	// Change a byte in the underlying physical entry
	pe, _ := inm.Get(ctx, "test")
	pe.Value[15]++
	require.NoError(t, inm.Put(ctx, pe))

	// Read from the barrier
	_, err = b.Get(ctx, "test")
	require.Error(t, err, "should fail!")
}

// Verify data sent through cannot be moved
func TestAESGCMBarrier_MoveIntegrityV1(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b.currentAESGCMVersionByte = AESGCMVersion1

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, entry))

	// Change the location of the underlying physical entry
	pe, _ := inm.Get(ctx, "test")
	pe.Key = "moved"
	require.NoError(t, inm.Put(ctx, pe))

	// Read from the barrier
	_, err = b.Get(ctx, "moved")
	require.NoError(t, err, "should succeed with version 1!")
}

func TestAESGCMBarrier_MoveIntegrityV2(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b.currentAESGCMVersionByte = AESGCMVersion2

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, entry))

	// Change the location of the underlying physical entry
	pe, _ := inm.Get(ctx, "test")
	pe.Key = "moved"
	require.NoError(t, inm.Put(ctx, pe))

	// Read from the barrier
	_, err = b.Get(ctx, "moved")
	require.Error(t, err, "should fail with version 2!")
}

func TestAESGCMBarrier_UpgradeV1toV2(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b.currentAESGCMVersionByte = AESGCMVersion1

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Put a logical entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	require.NoError(t, b.Put(ctx, entry))

	// Seal
	require.NoError(t, b.Seal())

	// Open again as version 2
	b = NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	b.currentAESGCMVersionByte = AESGCMVersion2

	// Unseal
	require.NoError(t, b.Unseal(ctx, key))

	// Check successful decryption
	_, err = b.Get(ctx, "test")
	require.NoError(t, err)
}

func TestEncrypt_Unique(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	require.NotNil(t, b.keyring, "barrier is sealed")

	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	term := b.keyring.ActiveTerm()
	primary, _ := b.aeadForTerm(term)

	first, err := b.encrypt("test", term, primary, entry.Value)
	require.NoError(t, err)
	second, err := b.encrypt("test", term, primary, entry.Value)
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, second), "improper random seeding detected")
}

func TestInitialize_KeyLength(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	long := []byte("ThisKeyDoesNotHaveTheRightLength!")
	middle := []byte("ThisIsASecretKeyAndMore")
	short := []byte("Key")

	require.Error(t, b.Initialize(ctx, long, nil))
	require.Error(t, b.Initialize(ctx, middle, nil))
	require.Error(t, b.Initialize(ctx, short, nil))
}

func TestEncrypt_BarrierEncryptor(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)

	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	cipher, err := b.Encrypt(ctx, "foo", []byte("quick brown fox"))
	require.NoError(t, err)
	plain, err := b.Decrypt(ctx, "foo", cipher)
	require.NoError(t, err)
	require.Equal(t, "quick brown fox", string(plain))
}

// Ensure Decrypt returns an error (rather than panic) when given a ciphertext
// that is nil or too short
func TestDecrypt_InvalidCipherLength(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)

	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
	key, err := b.GenerateKey()
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	var nilCipher []byte
	_, err = b.Decrypt(ctx, "", nilCipher)
	require.Error(t, err, "expected error when given nil cipher")

	emptyCipher := []byte{}
	_, err = b.Decrypt(ctx, "", emptyCipher)
	require.Error(t, err, "expected error when given empty cipher")

	badTermLengthCipher := make([]byte, 3)
	_, err = b.Decrypt(ctx, "", badTermLengthCipher)
	require.Error(t, err, "expected error when given cipher with too short term")
}

func TestAESGCMBarrier_ReloadKeyring(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	// Initialize and unseal
	key, _ := b.GenerateKey()

	ctx := t.Context()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	keyringRaw, err := inm.Get(ctx, KeyringPath)
	require.NoError(t, err)

	// Encrypt something to test cache invalidation
	_, err = b.Encrypt(ctx, "foo", []byte("quick brown fox"))
	require.NoError(t, err)

	{
		// Create a second barrier and rotate the keyring
		b2 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)
		require.NoError(t, b2.Unseal(ctx, key))
		_, err = b2.Rotate(ctx)
		require.NoError(t, err)
	}

	// Reload the keyring on the first
	require.NoError(t, b.ReloadKeyring(ctx))
	require.EqualValues(t, 2, b.keyring.ActiveTerm(), "failed to reload keyring")
	require.Empty(t, b.cache, "failed to clear cache")

	// Encrypt something to test cache invalidation
	_, err = b.Encrypt(ctx, "foo", []byte("quick brown fox"))
	require.NoError(t, err)

	// Restore old keyring to test rolling back
	require.NoError(t, inm.Put(ctx, keyringRaw))

	// Reload the keyring on the first
	require.NoError(t, b.ReloadKeyring(ctx))
	require.EqualValues(t, 1, b.keyring.ActiveTerm(), "failed to reload keyring")
	require.Empty(t, b.cache, "failed to clear cache")
}

func TestBarrier_LegacyRotate(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b1 := NewAESGCMBarrier(inm, "").(*TransactionalAESGCMBarrier)

	key, _ := b1.GenerateKey()

	ctx := t.Context()
	require.NoError(t, b1.Initialize(ctx, key, nil))
	require.NoError(t, b1.Unseal(ctx, key))

	k1 := b1.keyring.TermKey(1)
	k1.Encryptions = 0
	k1.InstallTime = time.Now().Add(-24 * 366 * time.Hour)

	require.NoError(t, b1.persistKeyring(ctx, b1.keyring))
	require.NoError(t, b1.Seal())
	require.NoError(t, b1.Unseal(ctx, key))

	reason, err := b1.CheckBarrierAutoRotate(ctx)
	require.NoError(t, err)
	require.Equal(t, legacyRotateReason, reason)
}

// TestBarrier_persistKeyring_Context checks that we get the right errors if
// the context is cancelled or times-out before the first part of persistKeyring
// is able to persist the keyring itself (i.e. we don't go on to try and persist
// the root key).
func TestBarrier_persistKeyring_Context(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		shouldCancel         bool
		isErrorExpected      bool
		expectedErrorMessage string
		contextTimeout       time.Duration
		testTimeout          time.Duration
	}{
		"cancelled": {
			shouldCancel:         true,
			isErrorExpected:      true,
			expectedErrorMessage: "failed to persist keyring: context canceled",
			contextTimeout:       8 * time.Second,
			testTimeout:          10 * time.Second,
		},
		"timeout-before-keyring": {
			isErrorExpected:      true,
			expectedErrorMessage: "failed to persist keyring: context deadline exceeded",
			contextTimeout:       1 * time.Nanosecond,
			testTimeout:          5 * time.Second,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			// Set up barrier
			backend, err := inmem.NewInmem(nil, corehelpers.NewTestLogger(t))
			require.NoError(t, err)
			barrier := NewAESGCMBarrier(backend, "").(*TransactionalAESGCMBarrier)
			key, _ := barrier.GenerateKey()
			require.NoError(t, barrier.Initialize(ctx, key, nil))
			require.NoError(t, barrier.Unseal(ctx, key))
			k := barrier.keyring.TermKey(1)
			k.Encryptions = 0
			k.InstallTime = time.Now().Add(-24 * 366 * time.Hour)

			// Persist the keyring
			ctx, cancel := context.WithTimeout(ctx, tc.contextTimeout)
			persistChan := make(chan error)
			go func() {
				if tc.shouldCancel {
					cancel()
				}
				persistChan <- barrier.persistKeyring(ctx, barrier.keyring)
			}()

			select {
			case err := <-persistChan:
				switch {
				case tc.isErrorExpected:
					require.Error(t, err)
					require.EqualError(t, err, tc.expectedErrorMessage)
				default:
					require.NoError(t, err)
				}
			case <-time.After(tc.testTimeout):
				t.Fatal("timeout reached")
			}
		})
	}
}

func TestAESGCMBarrier_Prefix_Basic(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	testBarrier(t, b)
}

func TestAESGCMBarrier_Prefix_Rotate(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	testBarrier_Rotate(t, b)
}

func TestAESGCMBarrier_Prefix_MissingRotateConfig(t *testing.T) {
	ctx := t.Context()

	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)

	// Initialize and unseal
	key, _ := b.GenerateKey()
	require.NoError(t, b.Initialize(ctx, key, nil))
	require.NoError(t, b.Unseal(ctx, key))

	// Write a keyring which lacks rotation config settings
	oldKeyring := b.keyring.Clone()
	oldKeyring.rotationConfig = KeyRotationConfig{}
	require.NoError(t, b.persistKeyring(ctx, oldKeyring))
	require.NoError(t, b.ReloadKeyring(ctx))

	require.True(t, defaultRotationConfig.Equals(b.keyring.rotationConfig),
		"expected empty rotation config to recover as default config")
}

func TestAESGCMBarrier_Prefix_Upgrade(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b1 := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	b2 := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	testBarrier_Upgrade(t, b1, b2)
}

func TestAESGCMBarrier_Prefix_Upgrade_RotateRootKey(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b1 := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	b2 := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	testBarrier_Upgrade_RotateRootKey(t, b1, b2)
}

func TestAESGCMBarrier_Prefix_RotateRootKey(t *testing.T) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, "prefix/").(*TransactionalAESGCMBarrier)
	testBarrier_RotateRootKey(t, b)
}
