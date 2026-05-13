// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/schema"
	"github.com/openbao/openbao/sdk/v2/helper/xor"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestGenerateRoot_Failure(t *testing.T) {
	t.Parallel()
	c, rootKey, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test/"}
	nsKeys := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testGenerateRoot_Failure(t, c, namespace.RootNamespace, rootKey)
	testGenerateRoot_Failure(t, c, ns, nsKeys["test/"])
}

func testGenerateRoot_Failure(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	req := logical.TestRequest(t, logical.UpdateOperation, "generate-root-token/attempt")
	req.Data["otp"] = "wrong length"
	_, err := c.systemBackend.HandleRequest(ctx, req)
	require.Error(t, err)

	req.Data["otp"] = ""
	res, err := c.systemBackend.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotEmpty(t, res.Data)

	nonce := res.Data["nonce"].(string)

	req = logical.TestRequest(t, logical.UpdateOperation, "generate-root-token/update")
	_, err = c.systemBackend.HandleRequest(ctx, req)
	require.Error(t, err)

	req.Data["nonce"] = nonce
	_, err = c.systemBackend.HandleRequest(ctx, req)
	require.Error(t, err)

	req.Data["key"] = "invalid-key"
	_, err = c.systemBackend.HandleRequest(ctx, req)
	require.Error(t, err)

	// make the key a valid hex.
	req.Data["key"] = hex.EncodeToString(keys[0])[:1]
	_, err = c.systemBackend.HandleRequest(ctx, req)
	require.Error(t, err)

	req.Data["key"] = hex.EncodeToString(keys[0])
	res, err = c.systemBackend.HandleRequest(ctx, req)
	require.NoError(t, err)

	expected := map[string]interface{}{
		"started":         true,
		"complete":        false,
		"progress":        1,
		"required":        3,
		"nonce":           nonce,
		"encoded_token":   "",
		"pgp_fingerprint": "",
	}
	require.Equal(t, expected, res.Data)
}

func TestGenerateRootAttempt(t *testing.T) {
	t.Parallel()
	c, rootKeys, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "test/"}
	nsKeys := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testGenerateRootAttempt(t, c, namespace.RootNamespace, "", rootKeys)
	testGenerateRootAttempt(t, c, namespace.RootNamespace, pgpkeys.TestPubKey1, rootKeys)
	testGenerateRootAttempt(t, c, ns, "", nsKeys["test/"])
	testGenerateRootAttempt(t, c, ns, pgpkeys.TestPubKey1, nsKeys["test/"])
}

func testGenerateRootAttempt(t *testing.T, c *Core, ns *namespace.Namespace, pgp string, keys [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	expected := map[string]interface{}{
		"started":         true,
		"complete":        false,
		"progress":        0,
		"required":        3,
		"otp":             "",
		"otp_length":      28,
		"pgp_fingerprint": "",
	}

	if ns.UUID != namespace.RootNamespaceUUID {
		expected["otp_length"] = 35
	}

	initReq := logical.TestRequest(t, logical.UpdateOperation, "generate-root-token/attempt")
	if pgp != "" {
		initReq.Data["pgp_key"] = pgp
		expected["pgp_fingerprint"] = "816938b8a29146fbe245dd29e7cbaf8e011db793"
	}

	res, err := c.systemBackend.HandleRequest(ctx, initReq)
	require.NoError(t, err)

	// copy nonce and otp
	expected["nonce"] = res.Data["nonce"]
	expected["otp"] = res.Data["otp"]
	require.Equal(t, expected, res.Data)

	// clear root generation attempt
	req := logical.TestRequest(t, logical.DeleteOperation, "generate-root-token/attempt")
	res, err = c.systemBackend.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, res)

	// check that the attempt has been cancelled
	req = logical.TestRequest(t, logical.ReadOperation, "generate-root-token/attempt")
	res, err = c.systemBackend.HandleRequest(ctx, req)
	require.NoError(t, err)

	uninitExp := map[string]interface{}{
		"started":    false,
		"complete":   false,
		"progress":   0,
		"required":   3,
		"otp":        "",
		"otp_length": expected["otp_length"],
	}
	require.Equal(t, uninitExp, res.Data)

	// again initialize the attempt
	res, err = c.systemBackend.HandleRequest(ctx, initReq)
	require.NoError(t, err)

	// copy nonce and otp
	otp := res.Data["otp"].(string)
	nonce := res.Data["nonce"].(string)
	expected["nonce"] = nonce
	expected["otp"] = otp
	require.Equal(t, expected, res.Data)

	delete(expected, "otp")
	delete(expected, "otp_length")
	expected["encoded_token"] = ""

	for i, key := range keys {
		req := logical.TestRequest(t, logical.UpdateOperation, "generate-root-token/update")
		req.Data["nonce"] = nonce
		req.Data["key"] = hex.EncodeToString(key)

		res, err = c.systemBackend.HandleRequest(ctx, req)
		require.NoError(t, err)

		expected["progress"] = i + 1
		if pgp != "" {
			expected["pgp_fingerprint"] = "816938b8a29146fbe245dd29e7cbaf8e011db793"
		}
		if i+1 == len(keys) {
			expected["complete"] = true
			expected["encoded_token"] = res.Data["encoded_token"]
		}
		require.Equal(t, expected, res.Data)
	}

	var newRootToken string
	if pgp != "" {
		decodedTokenBuf, err := pgpkeys.DecryptBytes(expected["encoded_token"].(string), pgpkeys.TestPrivKey1)
		require.NoError(t, err)
		require.NotNil(t, decodedTokenBuf)
		newRootToken = decodedTokenBuf.String()
	} else {
		tokenBytes, err := base64.RawStdEncoding.DecodeString(expected["encoded_token"].(string))
		require.NoError(t, err)

		tokenBytes, err = xor.XORBytes(tokenBytes, []byte(otp))
		require.NoError(t, err)
		newRootToken = string(tokenBytes)
	}

	var meta map[string]string
	expected = map[string]interface{}{
		"id":               newRootToken,
		"display_name":     "root",
		"meta":             meta,
		"num_uses":         0,
		"policies":         []string{"root"},
		"orphan":           true,
		"creation_ttl":     int64(0),
		"ttl":              int64(0),
		"path":             "auth/token/root",
		"explicit_max_ttl": int64(0),
		"expire_time":      nil,
		"entity_id":        "",
		"type":             "service",
	}

	if ns.UUID != namespace.RootNamespaceUUID {
		expected["display_name"] = fmt.Sprintf("%s_root", ns.ID)
		expected["namespace_path"] = ns.Path
		expected["path"] = fmt.Sprintf("namespaces/%s/%s", ns.UUID, expected["path"])
	}

	req = logical.TestRequest(t, logical.ReadOperation, "auth/token/lookup-self")
	req.ClientToken = newRootToken
	res, err = c.HandleRequest(ctx, req)
	require.NoError(t, err)

	expected["creation_time"] = res.Data["creation_time"]
	expected["accessor"] = res.Data["accessor"]

	require.Equal(t, expected, res.Data)
}

// TestSystemBackend_decodeToken ensures the correct decoding of the encoded token.
// It also ensures that the API fails if there is some payload missing.
func TestSystemBackend_decodeToken(t *testing.T) {
	encodedToken := "Bxg9JQQqOCNKBRICNwMIRzo2J3cWCBRi"
	otp := "3JhHkONiyiaNYj14nnD9xZQS"
	tokenExpected := "4RUmoevJ3lsLni9sTXcNnRE1"

	_, b, _ := testCoreSystemBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "decode-token")
	req.Data["encoded_token"] = encodedToken
	req.Data["otp"] = otp

	resp, err := b.HandleRequest(namespace.RootContext(t.Context()), req)
	require.NoError(t, err)

	schema.ValidateResponse(
		t,
		schema.GetResponseSchema(t, b.(*SystemBackend).Route(req.Path), req.Operation),
		resp,
		true,
	)

	token, ok := resp.Data["token"]
	require.True(t, ok)
	require.Equal(t, tokenExpected, token.(string))

	datas := []map[string]interface{}{
		nil,
		{"encoded_token": encodedToken},
		{"otp": otp},
	}
	for _, data := range datas {
		req.Data = data
		resp, err := b.HandleRequest(namespace.RootContext(t.Context()), req)
		require.Error(t, err)
		schema.ValidateResponse(
			t,
			schema.GetResponseSchema(t, b.(*SystemBackend).Route(req.Path), req.Operation),
			resp,
			true,
		)
	}
}
