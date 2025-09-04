// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
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
	testCore_GenerateRoot_Lifecycle_Common(t, c, rootKeys, namespace.RootNamespace)
}

func TestCore_NS_GenerateRoot_Lifecycle(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testCore_GenerateRoot_Lifecycle_Common(t, c, keysPerNamespace[ns.Path], ns)
}

func testCore_GenerateRoot_Lifecycle_Common(t *testing.T, c *Core, keys [][]byte, ns *namespace.Namespace) {
	// Verify update not allowed
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	if _, err := c.GenerateRootUpdate(ctx, keys[0], "", GenerateStandardRootTokenStrategy); err == nil {
		t.Fatal("no root generation in progress")
	}

	// Should be no progress
	num, err := c.GenerateRootProgress(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if num != 0 {
		t.Fatalf("bad: %d", num)
	}

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ns)
	require.Error(t, err)
	require.Nil(t, conf)

	// Cancel should be idempotent
	err = c.GenerateRootCancel(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	if err != nil {
		t.Fatal(err)
	}

	// Start a root generation
	err = c.GenerateRootInit(otp, "", GenerateStandardRootTokenStrategy, ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should get config
	conf, err = c.GenerateRootConfiguration(ns)
	require.NotNil(t, conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if conf == nil {
		t.Fatalf("expected conf != nil")
	}

	// Cancel should be clear
	err = c.GenerateRootCancel(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should be no config
	conf, err = c.GenerateRootConfiguration(ns)
	require.Error(t, err)
	require.Nil(t, conf)
}

func TestCore_GenerateRoot_Init(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	testCore_GenerateRoot_Init_Common(t, c, namespace.RootNamespace)

	bc := &SealConfig{SecretShares: 5, SecretThreshold: 3, StoredShares: 1}
	rc := &SealConfig{SecretShares: 5, SecretThreshold: 3}
	c, _, _, _ = TestCoreUnsealedWithConfigs(t, bc, rc)
	testCore_GenerateRoot_Init_Common(t, c, namespace.RootNamespace)
}

func TestCore_NS_GenerateRoot_Init(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	TestCoreCreateUnsealedNamespaces(t, c, ns)
	testCore_GenerateRoot_Init_Common(t, c, ns)
}

func testCore_GenerateRoot_Init_Common(t *testing.T, c *Core, ns *namespace.Namespace) {
	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}
	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	if err != nil {
		t.Fatal(err)
	}

	err = c.GenerateRootInit(otp, "", GenerateStandardRootTokenStrategy, ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Second should fail
	err = c.GenerateRootInit("", pgpkeys.TestPubKey1, GenerateStandardRootTokenStrategy, ns)
	if err == nil {
		t.Fatal("should fail")
	}
}

func TestCore_GenerateRoot_InvalidRootNonce(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	// Pass in root keys as they'll be invalid
	rootKeys[0][0]++
	testCore_GenerateRoot_InvalidRootNonce_Common(t, c, rootKeys, namespace.RootNamespace)
}

func TestCore_NS_GenerateRoot_InvalidRootNonce(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)
	keys := keysPerNamespace[ns.Path]
	keys[0][0]++
	testCore_GenerateRoot_InvalidRootNonce_Common(t, c, keys, ns)
}

func testCore_GenerateRoot_InvalidRootNonce_Common(t *testing.T, c *Core, keys [][]byte, ns *namespace.Namespace) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}

	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	if err != nil {
		t.Fatal(err)
	}

	err = c.GenerateRootInit(otp, "", GenerateStandardRootTokenStrategy, ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Fetch new config with generated nonce
	rgconf, err := c.GenerateRootConfiguration(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rgconf == nil {
		t.Fatal("bad: no rotate config received")
	}

	// Provide the nonce (invalid)
	_, err = c.GenerateRootUpdate(ctx, keys[0], "abcd", GenerateStandardRootTokenStrategy)
	if err == nil {
		t.Fatal("expected error")
	}

	// Provide the root (invalid)
	for _, key := range keys {
		_, err = c.GenerateRootUpdate(ctx, key, rgconf.Nonce, GenerateStandardRootTokenStrategy)
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCore_GenerateRoot_Update_OTP(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	testCore_GenerateRoot_Update_OTP_Common(t, c, rootKeys, namespace.RootNamespace)
}

func TestCore_NS_GenerateRoot_Update_OTP(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testCore_GenerateRoot_Update_OTP_Common(t, c, keysPerNamespace[ns.Path], ns)
}

func testCore_GenerateRoot_Update_OTP_Common(t *testing.T, c *Core, keys [][]byte, ns *namespace.Namespace) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	tokenLength := TokenLength
	if ns.UUID != namespace.RootNamespaceUUID {
		tokenLength = NSTokenLength
	}

	otp, err := base62.Random(TokenPrefixLength + tokenLength)
	if err != nil {
		t.Fatal(err)
	}

	// Start a root generation
	err = c.GenerateRootInit(otp, "", GenerateStandardRootTokenStrategy, ns)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch new config with generated nonce
	rkconf, err := c.GenerateRootConfiguration(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rkconf == nil {
		t.Fatal("bad: no root generation config received")
	}

	// Provide the keys
	var result *GenerateRootResult
	for _, key := range keys {
		result, err = c.GenerateRootUpdate(ctx, key, rkconf.Nonce, GenerateStandardRootTokenStrategy)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if result.EncodedToken != "" {
			break
		}
	}
	if result == nil {
		t.Fatal("Bad, result is nil")
	}

	encodedToken := result.EncodedToken

	// Should be no progress
	num, err := c.GenerateRootProgress(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if num != 0 {
		t.Fatalf("bad: %d", num)
	}

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ns)
	require.Error(t, err)
	require.Nil(t, conf)

	tokenBytes, err := base64.RawStdEncoding.DecodeString(encodedToken)
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err = xor.XORBytes(tokenBytes, []byte(otp))
	if err != nil {
		t.Fatal(err)
	}

	token := string(tokenBytes)

	// Ensure that the token is a root token
	te, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if te == nil {
		t.Fatal("token was nil")
	}
	if te.ID != token || te.Parent != "" ||
		len(te.Policies) != 1 || te.Policies[0] != "root" {
		t.Fatalf("bad: %#v", *te)
	}
}

func TestCore_GenerateRoot_Update_PGP(t *testing.T) {
	c, rootKeys, _ := TestCoreUnsealed(t)
	testCore_GenerateRoot_Update_PGP_Common(t, c, rootKeys, namespace.RootNamespace)
}

func TestCore_NS_GenerateRoot_Update_PGP(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test1/"}
	keysPerNamespace := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testCore_GenerateRoot_Update_PGP_Common(t, c, keysPerNamespace[ns.Path], ns)
}

func testCore_GenerateRoot_Update_PGP_Common(t *testing.T, c *Core, keys [][]byte, ns *namespace.Namespace) {
	// Start a root generation
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	err := c.GenerateRootInit("", pgpkeys.TestPubKey1, GenerateStandardRootTokenStrategy, ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Fetch new config with generated nonce
	rkconf, err := c.GenerateRootConfiguration(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rkconf == nil {
		t.Fatal("bad: no root generation config received")
	}

	// Provide the keys
	var result *GenerateRootResult
	for _, key := range keys {
		result, err = c.GenerateRootUpdate(ctx, key, rkconf.Nonce, GenerateStandardRootTokenStrategy)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if result.EncodedToken != "" {
			break
		}
	}
	if result == nil {
		t.Fatal("Bad, result is nil")
	}

	encodedToken := result.EncodedToken

	// Should be no progress
	num, err := c.GenerateRootProgress(ns)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if num != 0 {
		t.Fatalf("bad: %d", num)
	}

	// Should be no config
	conf, err := c.GenerateRootConfiguration(ns)
	require.Error(t, err)
	require.Nil(t, conf)

	ptBuf, err := pgpkeys.DecryptBytes(encodedToken, pgpkeys.TestPrivKey1)
	if err != nil {
		t.Fatal(err)
	}
	if ptBuf == nil {
		t.Fatal("Got nil plaintext key")
	}

	token := ptBuf.String()

	// Ensure that the token is a root token
	te, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if te == nil {
		t.Fatal("token was nil")
	}
	if te.ID != token || te.Parent != "" ||
		len(te.Policies) != 1 || te.Policies[0] != "root" {
		t.Fatalf("bad: %#v", *te)
	}
}
