// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/xor"
	"github.com/stretchr/testify/require"
)

func TestCore_GenerateRoot_Lifecycle(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)

	testCore_GenerateRoot_Lifecycle_Common(t, c, namespace.RootNamespace, rootKeys)
	testCore_GenerateRoot_Lifecycle_Common(t, c, ns, keysPerNamespace[ns.Path])
}

func testCore_GenerateRoot_Lifecycle_Common(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	// Verify update not allowed
	_, err := c.GenerateRootUpdate(ctx, keys[0], "", GenerateStandardRootTokenStrategy)
	require.Error(t, err)

	// Should be no progress
	num, err := c.GenerateRootProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, num)

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ctx)
	require.Error(t, err)
	require.Nil(t, conf)

	// Cancel should be idempotent
	require.NoError(t, c.GenerateRootCancel(ctx))

	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	require.NoError(t, err)

	// Start a root generation
	require.NoError(t, c.GenerateRootInit(ctx, otp, "", GenerateStandardRootTokenStrategy))

	// Should get config
	conf, err = c.GenerateRootConfiguration(ctx)
	require.NoError(t, err)
	require.NotNil(t, conf)

	// Cancel should be clear
	require.NoError(t, c.GenerateRootCancel(ctx))

	// Should be no config
	conf, err = c.GenerateRootConfiguration(ctx)
	require.Error(t, err)
	require.Nil(t, conf)
}

func TestCore_GenerateRoot_Init(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	TestCoreCreateUnsealedNamespaces(t, c, ns)

	testCore_GenerateRoot_Init_Common(t, c, namespace.RootNamespace)

	bc := &SealConfig{SecretShares: 5, SecretThreshold: 3}
	rc := &SealConfig{SecretShares: 5, SecretThreshold: 3}
	c, _, _, _ = TestCoreUnsealedWithConfigs(t, bc, rc)
	testCore_GenerateRoot_Init_Common(t, c, namespace.RootNamespace)

	testCore_GenerateRoot_Init_Common(t, c, ns)
}

func testCore_GenerateRoot_Init_Common(t *testing.T, c *Core, ns *namespace.Namespace) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	require.NoError(t, err)

	require.NoError(t, c.GenerateRootInit(ctx, otp, "", GenerateStandardRootTokenStrategy))

	// Second should fail
	require.Error(t, c.GenerateRootInit(ctx, "", pgpkeys.TestPubKey1, GenerateStandardRootTokenStrategy))
}

func TestCore_GenerateRoot_InvalidRootNonce(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)

	// incrementing root keys will make them invalid
	rootKeys[0][0]++
	keysPerNamespace[ns.Path][0][0]++

	testCore_GenerateRoot_InvalidRootNonce_Common(t, c, namespace.RootNamespace, rootKeys)
	testCore_GenerateRoot_InvalidRootNonce_Common(t, c, ns, keysPerNamespace[ns.Path])
}

func testCore_GenerateRoot_InvalidRootNonce_Common(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	require.NoError(t, err)

	require.NoError(t, c.GenerateRootInit(ctx, otp, "", GenerateStandardRootTokenStrategy))

	// Fetch new config with generated nonce
	rgconf, err := c.GenerateRootConfiguration(ctx)
	require.NoError(t, err)
	require.NotNil(t, rgconf)

	// Provide the invalid nonce
	_, err = c.GenerateRootUpdate(ctx, keys[0], "abcd", GenerateStandardRootTokenStrategy)
	require.Error(t, err)

	// Provide the invalid root key
	for _, key := range keys {
		_, err = c.GenerateRootUpdate(ctx, key, rgconf.Nonce, GenerateStandardRootTokenStrategy)
	}
	require.Error(t, err)
}

func TestCore_GenerateRoot_Update_OTP(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)

	testCore_GenerateRoot_Update_OTP_Common(t, c, namespace.RootNamespace, rootKeys)
	testCore_GenerateRoot_Update_OTP_Common(t, c, ns, keysPerNamespace[ns.Path])
}

func testCore_GenerateRoot_Update_OTP_Common(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	require.NoError(t, err)

	// Start a root generation
	require.NoError(t, c.GenerateRootInit(ctx, otp, "", GenerateStandardRootTokenStrategy))

	// Fetch new config with generated nonce
	rkconf, err := c.GenerateRootConfiguration(ctx)
	require.NoError(t, err)
	require.NotNil(t, rkconf)

	// Provide the keys
	var result *GenerateRootResult
	for _, key := range keys {
		result, err = c.GenerateRootUpdate(ctx, key, rkconf.Nonce, GenerateStandardRootTokenStrategy)
		require.NoError(t, err)
		if result.EncodedToken != "" {
			break
		}
	}
	require.NotNil(t, result)

	encodedToken := result.EncodedToken

	// Should be no progress
	num, err := c.GenerateRootProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, num)

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ctx)
	require.Error(t, err)
	require.Nil(t, conf)

	tokenBytes, err := base64.RawStdEncoding.DecodeString(encodedToken)
	require.NoError(t, err)

	tokenBytes, err = xor.XORBytes(tokenBytes, []byte(otp))
	require.NoError(t, err)

	token := string(tokenBytes)

	// Ensure that the token is a root token
	te, err := c.tokenStore.Lookup(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, te)

	require.False(t, te.ID != token || te.Parent != "" ||
		len(te.Policies) != 1 || te.Policies[0] != "root")
}

func TestCore_GenerateRoot_Update_PGP(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)

	testCore_GenerateRoot_Update_PGP_Common(t, c, namespace.RootNamespace, rootKeys)
	testCore_GenerateRoot_Update_PGP_Common(t, c, ns, keysPerNamespace[ns.Path])
}

func testCore_GenerateRoot_Update_PGP_Common(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	require.NoError(t, c.GenerateRootInit(ctx, "", pgpkeys.TestPubKey1, GenerateStandardRootTokenStrategy))

	// Fetch new config with generated nonce
	rkconf, err := c.GenerateRootConfiguration(ctx)
	require.NoError(t, err)
	require.NotNil(t, rkconf)

	// Provide the keys
	var result *GenerateRootResult
	for _, key := range keys {
		result, err = c.GenerateRootUpdate(ctx, key, rkconf.Nonce, GenerateStandardRootTokenStrategy)
		require.NoError(t, err)
		if result.EncodedToken != "" {
			break
		}
	}
	require.NotNil(t, result)

	encodedToken := result.EncodedToken

	// Should be no progress
	num, err := c.GenerateRootProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, num)

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ctx)
	require.Error(t, err)
	require.Nil(t, conf)

	ptBuf, err := pgpkeys.DecryptBytes(encodedToken, pgpkeys.TestPrivKey1)
	require.NoError(t, err)
	require.NotNil(t, ptBuf)

	token := ptBuf.String()

	// Ensure that the token is a root token
	te, err := c.tokenStore.Lookup(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, te)

	require.False(t, te.ID != token || te.Parent != "" ||
		len(te.Policies) != 1 || te.Policies[0] != "root")
}
