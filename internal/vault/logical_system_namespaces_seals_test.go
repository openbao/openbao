// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/pgpkeys"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	vaultseal "github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceBackend_SealStatus(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("returns error on non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/seal-status")
		resp, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, resp.Error(), ErrNotSealable.Error())
	})

	t.Run("can read seal status", func(t *testing.T) {
		TestCoreCreateUnsealedNamespaces(t, c, &namespace.Namespace{Path: "bar/"})

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/bar/seal-status")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "shamir", res.Data["type"])
		require.Equal(t, false, res.Data["sealed"])
		require.Equal(t, 3, res.Data["t"])
		require.Equal(t, 3, res.Data["n"])
		require.Equal(t, 0, res.Data["progress"])
	})
}

func TestNamespaceBackend_SealUnseal(t *testing.T) {
	t.Parallel()
	c, rootShares, root := TestCoreUnsealed(t)
	b := c.systemBackend

	rootCtx := namespace.RootContext(context.Background())
	t.Run("namespaces created with seal config are sealed by default", func(t *testing.T) {
		TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "foo/"})

		req := logical.TestRequest(t, logical.CreateOperation, "auth/token/create/foo")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/seal")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("cannot seal non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/seal")
		_, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, "invalid request", err.Error())
	})

	t.Run("can unseal namespace with required number of keyshares", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz")
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		keyShares := res.Data["key_shares"].([]string)
		require.Len(t, keyShares, 3)

		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "baz")
		require.NoError(t, err)
		require.NotNil(t, ns)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// call to sealed namespace should fail
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.NotNil(t, res.Error())

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyShares[0]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyShares[1]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// progress reset
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["sealed"])

		// call to unsealed namespace should succeed
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.NotNil(t, res)
		require.NoError(t, err)
	})

	t.Run("preserve mounts after unsealing namespaces", func(t *testing.T) {
		nsFoobar := &namespace.Namespace{Path: "foobar/"}
		keyshares := TestCoreCreateUnsealedNamespaces(t, c, nsFoobar)
		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "foobar")
		require.NoError(t, err)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// mount a kv engine
		req := logical.TestRequest(t, logical.UpdateOperation, "mounts/my_secrets")
		req.Data["type"] = "kv"
		_, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)

		// mount should appear
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err := b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_secrets/"])

		// store something to the mount
		req = logical.TestRequest(t, logical.UpdateOperation, "my_secrets/abc")
		req.Data["test_key"] = "test_value"
		_, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)

		// mount an auth and use it
		req = logical.TestRequest(t, logical.UpdateOperation, "auth/my_approle")
		req.Data["type"] = "approle"
		_, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_approle/"])

		req = logical.TestRequest(t, logical.CreateOperation, "auth/my_approle/role/myrole")
		req.Data["token_policies"] = []string{"default"}
		_, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)

		// then seal the namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/seal")
		_, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// unseal the namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][0])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][1])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 2, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][2])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// progress reset
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["sealed"])

		// mount should appear
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_secrets/"])

		// reading from mount should work
		req = logical.TestRequest(t, logical.ReadOperation, "my_secrets/abc")
		res, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "test_value", res.Data["test_key"])

		// auth should appear
		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_approle/"])

		// reading from auth should work
		req = logical.TestRequest(t, logical.ReadOperation, "auth/my_approle/role/myrole")
		res, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res)

		// Sealing and unsealing the root namespace should work.
		require.NoError(t, c.Seal(root))

		// Unseal the root namespace.
		for i, key := range rootShares {
			unseal, err := TestCoreUnseal(c, key)
			require.NoError(t, err)
			require.False(t, i+1 == len(rootShares) && !unseal)
		}

		// Namespace should now be sealed.
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.NotNil(t, res.Error())

		// Validate that mounts are gone.
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.Empty(t, res.Data)

		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.Empty(t, res.Data)

		// We should be able to unseal it.
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][0])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][1])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 2, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][2])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// progress reset
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["sealed"])

		// Now we should be able to list mounts again.
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_secrets/"])

		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_approle/"])
	})
}

func waitForMigrationToFinish(t *testing.T, c *Core, ns *namespace.Namespace, expectedType namespace.Type) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		got := c.NamespaceType(ns)
		assert.Equal(ct, expectedType, got)
	}, 10*time.Second, 10*time.Millisecond)
}

func parentBarrierOf(c *Core, ns *namespace.Namespace) barrier.SecurityBarrier {
	parentPath, ok := ns.ParentPath()
	if !ok {
		return nil
	}
	return c.sealManager.NamespaceBarrierByLongestPrefix(parentPath)
}

func writeNamespaceSecret(t *testing.T, c *Core, b logical.Backend, nsCtx context.Context, mountPath, subPath, value string) {
	t.Helper()

	req := logical.TestRequest(t, logical.ReadOperation, "mounts")
	res, err := b.HandleRequest(nsCtx, req)
	require.NoError(t, err)
	if res == nil || res.Data == nil || res.Data[mountPath+"/"] == nil {
		req = logical.TestRequest(t, logical.UpdateOperation, "mounts/"+mountPath)
		req.Data["type"] = "kv"
		_, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
	}

	req = logical.TestRequest(t, logical.UpdateOperation, mountPath+"/"+subPath)
	req.Data["test_key"] = value
	_, err = c.router.Route(nsCtx, req)
	require.NoError(t, err)
}

func readNamespaceSecret(t *testing.T, c *Core, nsCtx context.Context, mountPath, subPath string) *logical.Response {
	t.Helper()
	req := logical.TestRequest(t, logical.ReadOperation, mountPath+"/"+subPath)
	res, err := c.router.Route(nsCtx, req)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func unsealNamespace(t *testing.T, b logical.Backend, rootCtx context.Context, nsPath string, keyShares []string, threshold int) {
	t.Helper()
	for i := range threshold {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/"+nsPath+"/unseal")
		req.Data["key"] = keyShares[i]
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		if i+1 == threshold {
			require.Equal(t, false, res.Data["sealed"], "namespace should be unsealed after threshold shares")
		} else {
			require.Equal(t, true, res.Data["sealed"], "namespace should still be sealed before threshold")
		}
	}
}

func TestNamespaceBackend_MigrateBackend(t *testing.T) {
	t.Parallel()

	t.Run("normal to sealable migration returns key shares and preserves data", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		// create normal namespace
		ns := testCreateNamespace(t, rootCtx, b, "migrate", nil)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// write some data
		writeNamespaceSecret(t, c, b, nsCtx, "my_secrets", "abc", "before-migration")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

		// check namespace uses parent barrier
		oldBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.Same(t, parentBarrierOf(c, ns), oldBarrier, "normal namespace should share parent's barrier")

		// migrate to sealable namespace
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/migrate/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "in-progress", res.Data["status"])

		keyShares, ok := res.Data["key_shares"].([]string)
		require.True(t, ok, "expected key_shares in response, got %T", res.Data["key_shares"])
		require.Len(t, keyShares, 3)
		require.Equal(t, 2, res.Data["key_threshold"])

		waitForMigrationToFinish(t, c, ns, namespace.TypeSealable)

		newBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, oldBarrier, newBarrier, "sealable namespace should be backed by a new barrier after migration")
		require.NotSame(t, parentBarrierOf(c, ns), newBarrier, "sealable namespace should not share parent's barrier")

		require.False(t, c.NamespaceSealed(ns), "namespace should be unsealed after migration to sealable")
		got := readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc")
		require.Equal(t, "before-migration", got.Data["test_key"])
	})

	t.Run("sealable to normal migration collapses into parent barrier and preserves data", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		// create sealable namespace and unseal
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/collapse")
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		hexKeyShares := res.Data["key_shares"].([]string)
		require.Len(t, hexKeyShares, 3)

		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "collapse")
		require.NoError(t, err)
		require.Equal(t, namespace.TypeSealable, c.NamespaceType(ns))

		// make sure namespace barrier is not parent barrier
		sealableBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, parentBarrierOf(c, ns), sealableBarrier, "sealable namespace should not share parent's barrier")

		unsealNamespace(t, b, rootCtx, "collapse", hexKeyShares, 2)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// write some data
		writeNamespaceSecret(t, c, b, nsCtx, "my_secrets", "abc", "before-collapse")

		// migrate to normal namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/collapse/migrate-barrier")
		req.ClientToken = root
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "in-progress", res.Data["status"])
		require.Nil(t, res.Data["key_shares"], "no key shares expected when collapsing to normal")

		waitForMigrationToFinish(t, c, ns, namespace.TypeNormal)

		collapsedBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, sealableBarrier, collapsedBarrier, "collapsed namespace should not keep its old sealable barrier")
		require.Same(t, parentBarrierOf(c, ns), collapsedBarrier, "normal namespace should share parent's barrier after collapse")

		require.False(t, c.NamespaceSealed(ns), "normal namespace should not be sealed")
		got := readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc")
		require.Equal(t, "before-collapse", got.Data["test_key"])
	})

	t.Run("migrating to the same barrier type is a no-op", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		ns := testCreateNamespace(t, rootCtx, b, "noop", nil)
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/noop/migrate-barrier")
		req.ClientToken = root
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Nil(t, res, "expected nil response when migrating to the same barrier")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))
	})

	t.Run("pgp keys encrypt the returned key shares", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		// create normal namespace
		ns := testCreateNamespace(t, rootCtx, b, "pgp", nil)
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

		pgpKeys := []string{pgpkeys.TestPubKey1, pgpkeys.TestPubKey2, pgpkeys.TestPubKey3}
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/pgp/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		req.Data["pgp_keys"] = pgpKeys
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "in-progress", res.Data["status"])

		keyShares, ok := res.Data["key_shares"].([]string)
		require.True(t, ok, "expected key_shares in response, got %T", res.Data["key_shares"])
		require.Len(t, keyShares, 3)
		require.Equal(t, 2, res.Data["key_threshold"])

		for i, share := range keyShares {
			raw, err := hex.DecodeString(share)
			require.NoError(t, err)
			decrypted, err := pgpkeys.DecryptBytes(base64.StdEncoding.EncodeToString(raw), testPrivKey(t, i))
			require.NoError(t, err, "failed to decrypt share %d", i)
			_, err = hex.DecodeString(decrypted.String())
			require.NoError(t, err)
		}

		waitForMigrationToFinish(t, c, ns, namespace.TypeSealable)
	})

	t.Run("invalid seal config is rejected", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		ns := testCreateNamespace(t, rootCtx, b, "badconfig", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/badconfig/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "pkcs11" {}`
		_, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, err, "namespaces currently only support shamir seals")

		require.False(t, ns.Tainted, "namespace should not be tainted after a failed migration")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))
	})

	t.Run("pgp keys count must match shares", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		ns := testCreateNamespace(t, rootCtx, b, "pgpmismatch", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/pgpmismatch/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		req.Data["pgp_keys"] = []string{pgpkeys.TestPubKey1, pgpkeys.TestPubKey2}
		_, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, err, "count mismatch between number of provided PGP keys and number of shares")

		require.False(t, ns.Tainted, "namespace should not be tainted after a failed migration")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))
	})

	t.Run("round-trip normal to sealable to normal preserves data and barrier identity", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		ns := testCreateNamespace(t, rootCtx, b, "roundtrip-normal", nil)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
		writeNamespaceSecret(t, c, b, nsCtx, "my_secrets", "abc", "round-trip-value")

		originalBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.Same(t, parentBarrierOf(c, ns), originalBarrier, "normal namespace should share parent's barrier")

		// normal -> sealable
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/roundtrip-normal/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		hexKeyShares := res.Data["key_shares"].([]string)
		require.Len(t, hexKeyShares, 3)
		waitForMigrationToFinish(t, c, ns, namespace.TypeSealable)

		sealableBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, originalBarrier, sealableBarrier, "sealable namespace should be backed by a new barrier")
		require.False(t, c.NamespaceSealed(ns), "namespace should be unsealed after migration to sealable")
		require.Equal(t, "round-trip-value", readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc").Data["test_key"])

		// sealable -> normal
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/roundtrip-normal/migrate-barrier")
		req.ClientToken = root
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Nil(t, res.Data["key_shares"], "no key shares expected when collapsing to normal")
		waitForMigrationToFinish(t, c, ns, namespace.TypeNormal)

		finalBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, sealableBarrier, finalBarrier, "collapsed namespace should not keep its old sealable barrier")
		require.Same(t, originalBarrier, finalBarrier, "collapsed namespace should be backed by the original parent barrier again")
		require.False(t, c.NamespaceSealed(ns), "normal namespace should not be sealed")
		require.Equal(t, "round-trip-value", readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc").Data["test_key"])
	})

	t.Run("round-trip sealable to normal to sealable preserves data and creates a fresh barrier", func(t *testing.T) {
		t.Parallel()
		c, _, root := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/roundtrip-sealable")
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		firstHexKeyShares := res.Data["key_shares"].([]string)
		require.Len(t, firstHexKeyShares, 3)

		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "roundtrip-sealable")
		require.NoError(t, err)
		require.Equal(t, namespace.TypeSealable, c.NamespaceType(ns))

		firstSealableBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, parentBarrierOf(c, ns), firstSealableBarrier, "sealable namespace should not share parent's barrier")

		unsealNamespace(t, b, rootCtx, "roundtrip-sealable", firstHexKeyShares, 2)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
		writeNamespaceSecret(t, c, b, nsCtx, "my_secrets", "abc", "sealable-round-trip-value")

		// sealable -> normal
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/roundtrip-sealable/migrate-barrier")
		req.ClientToken = root
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Nil(t, res.Data["key_shares"], "no key shares expected when collapsing to normal")
		waitForMigrationToFinish(t, c, ns, namespace.TypeNormal)

		normalBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, firstSealableBarrier, normalBarrier, "collapsed namespace should not keep its old sealable barrier")
		require.Same(t, parentBarrierOf(c, ns), normalBarrier, "normal namespace should share parent's barrier")
		require.False(t, c.NamespaceSealed(ns), "normal namespace should not be sealed")
		require.Equal(t, "sealable-round-trip-value", readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc").Data["test_key"])

		// normal -> sealable
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/roundtrip-sealable/migrate-barrier")
		req.ClientToken = root
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		secondHexKeyShares := res.Data["key_shares"].([]string)
		require.Len(t, secondHexKeyShares, 3)
		waitForMigrationToFinish(t, c, ns, namespace.TypeSealable)

		secondSealableBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
		require.NotSame(t, normalBarrier, secondSealableBarrier, "re-sealed namespace should be backed by a new barrier")
		require.NotSame(t, firstSealableBarrier, secondSealableBarrier, "re-sealed namespace must not reuse the original sealable barrier")
		require.False(t, c.NamespaceSealed(ns), "namespace should be unsealed after migration to sealable")
		require.Equal(t, "sealable-round-trip-value", readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc").Data["test_key"])
	})

	t.Run("migration requires sudo privileges", func(t *testing.T) {
		t.Parallel()
		c, _, _ := TestCoreUnsealed(t)
		b := c.systemBackend
		rootCtx := namespace.RootContext(context.Background())

		ns := testCreateNamespace(t, rootCtx, b, "sudo", nil)
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

		// no token request
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/sudo/migrate-barrier")
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorIs(t, err, logical.ErrPermissionDenied)
		require.Nil(t, res, "no response expected on permission denial")

		require.False(t, ns.Tainted, "namespace should not be tainted after a denied migration")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

		// invalid token
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/sudo/migrate-barrier")
		req.ClientToken = "invalid-token"
		req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorIs(t, err, logical.ErrPermissionDenied)
		require.Nil(t, res, "no response expected on permission denial")
		require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))
	})
}

func testPrivKey(t *testing.T, i int) string {
	t.Helper()
	switch i {
	case 0:
		return pgpkeys.TestPrivKey1
	case 1:
		return pgpkeys.TestPrivKey2
	case 2:
		return pgpkeys.TestPrivKey3
	default:
		t.Fatalf("no test private key for index %d", i)
		return ""
	}
}

// waitForActiveAndStandbys waits until the cluster has one active core and at
// least one standby core that are ready. This is the inline equivalent of
// testhelpers.WaitForActiveNodeAndStandbys, which cannot be imported here due
// to an import cycle (testhelpers imports vault).
func waitForActiveAndStandbys(t *testing.T, cluster *TestCluster) (*TestClusterCore, []*TestClusterCore) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var active int
		var standby int
		for _, core := range cluster.Cores {
			if core.Standby() {
				standby++
			} else {
				active++
			}
		}
		assert.Equal(ct, 1, active, "expected exactly one active core")
		assert.GreaterOrEqual(ct, standby, 1, "expected at least one standby core")
	}, 30*time.Second, 100*time.Millisecond)

	var activeCore *TestClusterCore
	var standbyCores []*TestClusterCore
	for _, core := range cluster.Cores {
		if core.Standby() {
			standbyCores = append(standbyCores, core)
		} else {
			activeCore = core
		}
	}
	require.NotNil(t, activeCore, "expected an active core")
	require.NotEmpty(t, standbyCores, "expected at least one standby core")
	return activeCore, standbyCores
}

func TestNamespaceBackend_MigrateBarrier_Cluster(t *testing.T) {
	t.Parallel()

	cluster := NewTestCluster(t, nil, nil)
	cluster.Start()
	defer cluster.Cleanup()

	active, _ := waitForActiveAndStandbys(t, cluster)

	rootCtx := namespace.RootContext(context.Background())
	root := cluster.RootToken
	b := active.systemBackend

	// create normal namespace
	ns := testCreateNamespace(t, rootCtx, b, "cluster-migrate", nil)
	require.Equal(t, namespace.TypeNormal, active.NamespaceType(ns))

	// wait until namespace is propagated
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, core := range cluster.Cores {
			got, err := core.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
			assert.NoError(ct, err)
			assert.NotNil(ct, got, "namespace not yet visible on core %d", core.coreNumber)
		}
	}, 10*time.Second, 50*time.Millisecond)

	nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
	writeNamespaceSecret(t, active.Core, b, nsCtx, "my_secrets", "abc", "cluster-before")

	// normal -> sealable
	req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/cluster-migrate/migrate-barrier")
	req.ClientToken = root
	req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
	res, err := b.HandleRequest(rootCtx, req)
	require.NoError(t, err)
	require.Equal(t, "in-progress", res.Data["status"])

	activeNs, err := active.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
	require.NoError(t, err)
	require.True(t, activeNs.Tainted, "namespace should be tainted on active node during migration")

	readReq := logical.TestRequest(t, logical.ReadOperation, "my_secrets/abc")
	readReq.ClientToken = root
	_, err = active.HandleRequest(nsCtx, readReq)
	require.Error(t, err, "request to tainted namespace should fail")

	waitForMigrationToFinish(t, active.Core, ns, namespace.TypeSealable)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, core := range cluster.Cores {
			got, err := core.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
			if assert.NoError(ct, err) && assert.NotNil(ct, got) {
				assert.False(ct, got.Tainted, "namespace should not be tainted on core %d after migration", core.coreNumber)
			}
		}
	}, 5*time.Minute, 100*time.Millisecond)

	require.False(t, active.NamespaceSealed(ns), "namespace should be unsealed after migration")

	// check that data is still readable after migration
	got := readNamespaceSecret(t, active.Core, nsCtx, "my_secrets", "abc")
	require.Equal(t, "cluster-before", got.Data["test_key"])
}

// failingBarrier wraps a SecurityBarrier and fails Get/ListPage after a
// configurable number of successful calls. This lets us test that the migration
// transaction is aborted and the namespace is left in a consistent state.
type failingBarrier struct {
	barrier.SecurityBarrier
	failAfter int32
	calls     atomic.Int32
}

func newFailingBarrier(b barrier.SecurityBarrier, failAfter int32) *failingBarrier {
	return &failingBarrier{
		SecurityBarrier: b,
		failAfter:       failAfter,
	}
}

var errInjectedFailure = errors.New("injected storage failure")

func (f *failingBarrier) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if f.calls.Add(1) > f.failAfter {
		return nil, errInjectedFailure
	}
	return f.SecurityBarrier.Get(ctx, key)
}

func (f *failingBarrier) ListPage(ctx context.Context, prefix, after string, limit int) ([]string, error) {
	if f.calls.Add(1) > f.failAfter {
		return nil, errInjectedFailure
	}
	return f.SecurityBarrier.ListPage(ctx, prefix, after, limit)
}

// TestNamespaceBackend_MigrateBarrier_FailureRecovery verifies that when a
// namespace barrier migration fails, the transaction is aborted and any other
// changes made are rolled back.
func TestNamespaceBackend_MigrateBarrier_FailureRecovery(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	// create normal namespace
	ns := testCreateNamespace(t, rootCtx, b, "fail-migrate", nil)
	nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
	writeNamespaceSecret(t, c, b, nsCtx, "my_secrets", "abc", "before-failure")
	require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns))

	oldBarrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
	oldView := barrier.NewView(oldBarrier, NamespaceStoragePathPrefix(ns))

	keysBeforeMigration, err := recurseListKeys(rootCtx, oldView, "")
	require.NoError(t, err)

	// taint the namespace manually
	parentNs, err := namespace.FromContext(rootCtx)
	require.NoError(t, err)
	require.NoError(t, c.namespaceStore.taintNamespace(rootCtx, parentNs, ns))

	// create new barrier
	sealConfig := &SealConfig{
		Type:            "shamir",
		SecretShares:    3,
		SecretThreshold: 2,
	}
	metaPrefix := NamespaceStoragePathPrefix(ns)
	seal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
	seal.SetCore(c)
	seal.SetMetaPrefix(metaPrefix)
	seal.SetConfigAccess(oldBarrier)

	nsSealCtx := namespace.ContextWithNamespace(rootCtx, ns)
	require.NoError(t, seal.Init(nsSealCtx))

	newBarrier := barrier.NewAESGCMBarrier(c.physical, ns)
	_, err = c.sealManager.initializeBarrier(nsSealCtx, newBarrier, seal, sealConfig)
	require.NoError(t, err)

	// create migration job with a failing old barrier that errors after the
	// first Get/ListPage call
	failingOld := newFailingBarrier(oldBarrier, 3)

	job := c.namespaceStore.newNamespaceBarrierMigrationJob(
		oldBarrier, failingOld, newBarrier, parentNs, ns, seal, sealConfig,
	)

	err = job.Execute()
	require.Error(t, err, "migration job should fail when old barrier returns an error")

	// old barrier checks
	activeNs, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "fail-migrate")
	require.NoError(t, err)
	require.False(t, activeNs.Tainted, "namespace should not remain tainted after a failed migration")

	require.Equal(t, namespace.TypeNormal, c.NamespaceType(ns), "namespace type should not have changed")

	oldKeys, err := recurseListKeys(rootCtx, oldView, "")
	require.NoError(t, err)
	assert.NotEmpty(t, oldKeys, "data should still be accessible through the old barrier after a failed migration")
	assert.Equal(t, keysBeforeMigration, oldKeys, "there should be no new keys or keys deleted compared to before the migration attempt")
	for _, key := range knownNamespaceCoreEntriesToCleanup {
		assert.NotContains(t, oldKeys, key, "%q should have been deleted after failed migration", key)
	}
	for _, key := range oldKeys {
		_, err = oldView.Get(rootCtx, key)
		assert.NoError(t, err, "reading %q through old barrier should still be possible after transaction rollback", key)
	}

	// new barrier checks
	newView := barrier.NewView(newBarrier, NamespaceStoragePathPrefix(ns))
	for _, key := range oldKeys {
		_, err := newView.Get(rootCtx, key)
		assert.Error(t, err, "reading %q through new barrier should fail after transaction rollback", key)
	}

	// untaint namespace
	require.NoError(t, c.namespaceStore.untaintNamespace(rootCtx, parentNs, ns))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		got := readNamespaceSecret(t, c, nsCtx, "my_secrets", "abc")
		assert.Equal(ct, "before-failure", got.Data["test_key"])
	}, 10*time.Second, 10*time.Millisecond)
}
