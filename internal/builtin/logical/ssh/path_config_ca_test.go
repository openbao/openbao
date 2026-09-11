// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	timeout = 10 * time.Second
	tick    = 200 * time.Millisecond
)

func TestSSH_ConfigCASubmitDefaultIssuer(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// create a role to issue against
	roleName := "ca-issuance"
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data: map[string]any{
			"allow_user_certificates": true,
			"allowed_users":           "*",
			"key_type":                "ca",
			"default_user":            testUserName,
			"ttl":                     "30m0s",
		},
		Storage: s,
	}
	resp, err := b.HandleRequest(t.Context(), roleReq)
	require.NoError(t, err, "cannot create role")
	require.Nil(t, resp, "unexpected response creating role")

	// create the default CA issuer
	defaultCaReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(t.Context(), defaultCaReq)
	require.NoError(t, err, "cannot create default CA issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response creating default CA issuer")

	caPublicKey := strings.TrimSpace(resp.Data["public_key"].(string))
	require.NotEmpty(t, caPublicKey, "empty CA issuer public key")

	// prepare test container to test SSH
	cleanup, sshAddress := prepareTestContainer(t, dockerImageTagSupportsRSA1, caPublicKey)
	t.Cleanup(cleanup)

	// sign a key
	signReq := &logical.Request{
		Path:      "sign/" + roleName,
		Operation: logical.UpdateOperation,
		Data: map[string]any{
			"public_key":       testKeyToSignPublic,
			"valid_principals": testUserName,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(t.Context(), signReq)
	require.NoError(t, err, "cannot sign key")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response signing key")

	signedKey := strings.TrimSpace(resp.Data["signed_key"].(string))
	require.NotEmpty(t, signedKey, "empty signed key")

	privateKey, err := ssh.ParsePrivateKey([]byte(testKeyToSignPrivate))
	require.NoError(t, err, "error parsing private key")

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKey))
	require.NoError(t, err, "error parsing signed key")

	certSigner, err := ssh.NewCertSigner(parsedKey.(*ssh.Certificate), privateKey)
	require.NoError(t, err, "error creating cert signer")

	// Insert a remote call inside the EventuallyWithT loop.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		errRemote := testSSH(testUserName, sshAddress, ssh.PublicKeys(certSigner), "date")
		require.NoError(collect, errRemote, "error verifying testing SSH")
	}, timeout, tick)
}

func TestSSH_ConfigCAKeyTypes(t *testing.T) {
	t.Parallel()
	var err error
	b, s := CreateBackendWithStorage(t)

	cases := []struct {
		keyType string
		keyBits int
	}{
		{"ssh-rsa", 2048},
		{"ssh-rsa", 4096},
		{"ssh-rsa", 0},
		{"rsa", 2048},
		{"rsa", 4096},
		{"ecdsa-sha2-nistp256", 0},
		{"ecdsa-sha2-nistp384", 0},
		{"ecdsa-sha2-nistp521", 0},
		{"ec", 256},
		{"ec", 384},
		{"ec", 521},
		{"ec", 0},
		{"ssh-ed25519", 0},
		{"ed25519", 0},
	}

	// Create a role for ssh signing.
	roleOptions := map[string]any{
		"allow_user_certificates": true,
		"allowed_users":           "*",
		"key_type":                "ca",
		"ttl":                     "30s",
		"not_before_duration":     "2h",
	}
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/ca-issuance",
		Data:      roleOptions,
		Storage:   s,
	}
	_, err = b.HandleRequest(t.Context(), roleReq)
	require.NoError(t, err, "cannot create role to issue against")

	for index, scenario := range cases {
		createDeleteHelper(t, b, s, index, scenario.keyType, scenario.keyBits)
	}
}

func TestSSH_ConfigCAPurgeIssuers(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// submit multiple CA issuers
	caIssuerOptions := []struct {
		keyType string
		keyBits int
	}{
		{"rsa", 2048},
		{"rsa", 4096},
		{"ed25519", 0},
	}

	for id, opts := range caIssuerOptions {
		defaultCaReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Data: map[string]any{
				"key_type":             opts.keyType,
				"key_bits":             opts.keyBits,
				"generate_signing_key": true,
			},
			Storage: s,
		}
		resp, err := b.HandleRequest(t.Context(), defaultCaReq)
		require.NoError(t, err, "issuer %d: cannot create CA issuer to perform signing operations", id)
		require.False(t, resp != nil && resp.IsError(), "issuer %d: unexpected error response creating CA issuer", id)
	}

	// list all isuers make sure all are present
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "issuers",
		Storage:   s,
	}
	resp, err := b.HandleRequest(t.Context(), listReq)
	require.NoError(t, err, "cannot list issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response listing issuers")

	require.Equal(t, 3, len(resp.Data["keys"].([]string)), "expected three issuers")

	// purge all issuers
	purgeReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(t.Context(), purgeReq)
	require.NoError(t, err, "cannot purge CA issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response purging CA issuers")

	// list all isuers make sure none are present
	resp, err = b.HandleRequest(t.Context(), listReq)
	require.NoError(t, err, "cannot list issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response listing issuers")

	require.True(t, len(resp.Data) == 0 || len(resp.Data["keys"].([]string)) == 0, "expected no issuers")
}

func TestSSH_ConfigCAParams(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	t.Run("GenerateSigningKeyFalse", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]any{
				"generate_signing_key": false,
			},
		})
		require.Nil(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Data["error"].(string), "missing public_key")
	})

	t.Run("NoPrivateKeySet", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]any{
				"generate_signing_key": false,
				"public_key":           testCAPublicKey,
			},
		})
		require.Nil(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Data["error"].(string), "only one of public_key and private_key set")
	})

	t.Run("GenerateSigningKeyTrue", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]any{
				"generate_signing_key": true,
			},
		})
		require.Nil(t, err)
		require.False(t, resp.IsError())
		require.NotEmpty(t, resp.Data["issuer_id"].(string))
		require.Contains(t, resp.Data["public_key"].(string), "ssh-rsa")
	})

	t.Run("GenerateSigningKeyTrueAndKeyMaterial", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]any{
				"generate_signing_key": true,
				"public_key":           testCAPublicKey,
				"private_key":          testCAPrivateKey,
			},
		})
		require.Nil(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Data["error"].(string), "public_key and private_key must not be set when generate_signing_key is set to true")
	})

	t.Run("NoParametersSet", func(t *testing.T) {
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
		})
		require.Nil(t, err)
		require.False(t, resp.IsError())
		require.NotEmpty(t, resp.Data["issuer_id"].(string))
		require.Contains(t, resp.Data["public_key"].(string), "ssh-rsa")
	})
}

func TestSSH_ConfigCAReadDefaultIssuer(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// submit an issuer and set as default
	createCaIssuerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuers/import",
		Data: map[string]any{
			"set_as_default": true,
		},
		Storage: s,
	}
	resp, err := b.HandleRequest(t.Context(), createCaIssuerReq)
	require.NoError(t, err, "cannot submit CA issuer as default")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response submitting CA issuer as default")

	// override existing 'default with 'config/ca' endpoint
	configDefaultCARequest := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Data: map[string]any{
			"private_key": testCAPrivateKey,
			"public_key":  testCAPublicKey,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(t.Context(), configDefaultCARequest)
	require.NoError(t, err, "cannot submit a new CA and override existing 'default'")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response submitting new CA")

	// read the 'default' issuer
	readDefaultIssuerRequest := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(t.Context(), readDefaultIssuerRequest)
	require.NoError(t, err, "cannot read default issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response reading default issuer")

	require.NotEmpty(t, resp.Data["public_key"], "expected a public key but got none")
	require.Equal(t, testCAPublicKey, resp.Data["public_key"], "expected public key %v but got %v", testCAPublicKey, resp.Data["public_key"])
}

func createDeleteHelper(t *testing.T, b logical.Backend, s logical.Storage, index int, keyType string, keyBits int) {
	// Check that we can create a new key of the specified type
	caReq := &logical.Request{
		Path:      "config/ca",
		Operation: logical.UpdateOperation,
		Storage:   s,
	}
	caReq.Data = map[string]any{
		"generate_signing_key": true,
		"key_type":             keyType,
		"key_bits":             keyBits,
	}
	resp, err := b.HandleRequest(t.Context(), caReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)
	require.Contains(t, resp.Data["public_key"].(string), caReq.Data["key_type"].(string), "bad case %v: expected public key of type %v but was %v", index, caReq.Data["key_type"], resp.Data["public_key"])

	issueOptions := map[string]any{
		"public_key":       testCAPublicKeyEd25519,
		"valid_principals": "toor",
	}
	issueReq := &logical.Request{
		Path:      "sign/ca-issuance",
		Operation: logical.UpdateOperation,
		Data:      issueOptions,
		Storage:   s,
	}
	resp, err = b.HandleRequest(t.Context(), issueReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)

	// Delete the configured keys
	caReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(t.Context(), caReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)
}
