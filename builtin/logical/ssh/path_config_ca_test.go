// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSSH_ConfigCASubmitDefaultIssuer(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	testKeyToSignPrivate := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwn1V2xd/EgJXIY53fBTtc20k/ajekqQngvkpFSwNHW63XNEQK8Ll
FOCyGXoje9DUGxnYs3F/ohfsBBWkLNfU7fiENdSJL1pbkAgJ+2uhV9sLZjvYhikrXWoyJX
LDKfY12LjpcBS2HeLMT04laZ/xSJrOBEJHGzHyr2wUO0NUQUQPUODAFhnHKgvvA4Uu79UY
gcdThF4w83+EAnE4JzBZMKPMjzy4u1C0R/LoD8DuapHwX6NGWdEUvUZZ+XRcIWeCOvR0ne
qGBRH35k1Mv7k65d7kkE0uvM5Z36erw3tdoszxPYf7AKnO1DpeU2uwMcym6xNwfwynKjhL
qL/Mgi4uRwAAA8iAsY0zgLGNMwAAAAdzc2gtcnNhAAABAQDCfVXbF38SAlchjnd8FO1zbS
T9qN6SpCeC+SkVLA0dbrdc0RArwuUU4LIZeiN70NQbGdizcX+iF+wEFaQs19Tt+IQ11Ikv
WluQCAn7a6FX2wtmO9iGKStdajIlcsMp9jXYuOlwFLYd4sxPTiVpn/FIms4EQkcbMfKvbB
Q7Q1RBRA9Q4MAWGccqC+8DhS7v1RiBx1OEXjDzf4QCcTgnMFkwo8yPPLi7ULRH8ugPwO5q
kfBfo0ZZ0RS9Rln5dFwhZ4I69HSd6oYFEffmTUy/uTrl3uSQTS68zlnfp6vDe12izPE9h/
sAqc7UOl5Ta7AxzKbrE3B/DKcqOEuov8yCLi5HAAAAAwEAAQAAAQABns2yT5XNbpuPOgKg
1APObGBchKWmDxwNKUpAVOefEScR7OP3mV4TOHQDZlMZWvoJZ8O4av+nOA/NUOjXPs0VVn
azhBvIezY8EvUSVSk49Cg6J9F7/KfR1WqpiTU7CkQUlCXNuz5xLUyKdJo3MQ/vjOqeenbh
MR9Wes4IWF1BVe4VOD6lxRsjwuIieIgmScW28FFh2rgsEfO2spzZ3AWOGExw+ih757hFz5
4A2fhsQXP8m3r8m7iiqcjTLWXdxTUk4zot2kZEjbI4Avk0BL+wVeFq6f/y+G+g5edqSo7j
uuSgzbUQtA9PMnGxhrhU2Ob7n3VGdya7WbGZkaKP8zJhAAAAgQC3bJurmOSLIi3KVhp7lD
/FfxwXHwVBFALCgq7EyNlkTz6RDoMFM4eOTRMDvsgWxT+bSB8R8eg1sfgY8rkHOuvTAVI5
3oEYco3H7NWE9X8Zt0lyhO1uaE49EENNSQ8hY7R3UIw5becyI+7ZZxs9HkBgCQCZzSjzA+
SIyAoMKM261AAAAIEA+PCkcDRp3J0PaoiuetXSlWZ5WjP3CtwT2xrvEX9x+ZsDgXCDYQ5T
osxvEKOGSfIrHUUhzZbFGvqWyfrziPe9ypJrtCM7RJT/fApBXnbWFcDZzWamkQvohst+0w
XHYCmNoJ6/Y+roLv3pzyFUmqRNcrQaohex7TZmsvHJT513UakAAACBAMgBXxH8DyNYdniX
mIXEto4GqMh4rXdNwCghfpyWdJE6vCyDt7g7bYMq7AQ2ynSKRtQDT/ZgQNfSbilUq3iXz7
xNZn5U9ndwFs90VmEpBup/PmhfX+Gwt5hQZLbkKZcgQ9XrhSKdMxVm1yy/fk0U457enlz5
cKumubUxOfFdy1ZvAAAAEm5jY0BtYnAudWJudC5sb2NhbA==
-----END OPENSSH PRIVATE KEY-----
`
	testKeyToSignPublic := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCfVXbF38SAlchjnd8FO1zbST9qN6SpCeC+SkVLA0dbrdc0RArwuUU4LIZeiN70NQbGdizcX+iF+wEFaQs19Tt+IQ11IkvWluQCAn7a6FX2wtmO9iGKStdajIlcsMp9jXYuOlwFLYd4sxPTiVpn/FIms4EQkcbMfKvbBQ7Q1RBRA9Q4MAWGccqC+8DhS7v1RiBx1OEXjDzf4QCcTgnMFkwo8yPPLi7ULRH8ugPwO5qkfBfo0ZZ0RS9Rln5dFwhZ4I69HSd6oYFEffmTUy/uTrl3uSQTS68zlnfp6vDe12izPE9h/sAqc7UOl5Ta7AxzKbrE3B/DKcqOEuov8yCLi5H `

	// create a role to issue against
	roleName := "ca-issuance"
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data: map[string]interface{}{
			"allow_user_certificates": true,
			"allowed_users":           "*",
			"key_type":                "ca",
			"default_user":            testUserName,
			"ttl":                     "30m0s",
		},
		Storage: s,
	}
	resp, err := b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err, "cannot create role")
	require.Nil(t, resp, "unexpected response creating role")

	// create the default CA issuer
	defaultCaReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), defaultCaReq)
	require.NoError(t, err, "cannot create default CA issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response creating default CA issuer")

	caPublicKey := strings.TrimSpace(resp.Data["public_key"].(string))
	require.NotEmpty(t, caPublicKey, "empty CA issuer public key")

	// prepare test container to test SSH
	cleanup, sshAddress := prepareTestContainer(t, dockerImageTagSupportsRSA1, caPublicKey)
	defer cleanup()

	// sign a key
	signReq := &logical.Request{
		Path:      "sign/" + roleName,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"public_key":       testKeyToSignPublic,
			"valid_principals": testUserName,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), signReq)
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

	err = testSSH(testUserName, sshAddress, ssh.PublicKeys(certSigner), "date")
	require.NoError(t, err, "error verifying testing SSH")
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
	roleOptions := map[string]interface{}{
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
	_, err = b.HandleRequest(context.Background(), roleReq)
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
			Data: map[string]interface{}{
				"key_type":             opts.keyType,
				"key_bits":             opts.keyBits,
				"generate_signing_key": true,
			},
			Storage: s,
		}
		resp, err := b.HandleRequest(context.Background(), defaultCaReq)
		require.NoError(t, err, "issuer %d: cannot create CA issuer to perform signing operations", id)
		require.False(t, resp != nil && resp.IsError(), "issuer %d: unexpected error response creating CA issuer", id)
	}

	// list all isuers make sure all are present
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "issuers",
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), listReq)
	require.NoError(t, err, "cannot list issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response listing issuers")

	require.Equal(t, 3, len(resp.Data["keys"].([]string)), "expected three issuers")

	// purge all issuers
	purgeReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), purgeReq)
	require.NoError(t, err, "cannot purge CA issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response purging CA issuers")

	// list all isuers make sure none are present
	resp, err = b.HandleRequest(context.Background(), listReq)
	require.NoError(t, err, "cannot list issuers")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response listing issuers")

	require.True(t, len(resp.Data) == 0 || len(resp.Data["keys"].([]string)) == 0, "expected no issuers")
}

func TestSSH_ConfigCAParams(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	t.Run("GenerateSigningKeyFalse", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]interface{}{
				"generate_signing_key": false,
			},
		})
		require.Nil(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Data["error"].(string), "missing public_key")
	})

	t.Run("NoPrivateKeySet", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]interface{}{
				"generate_signing_key": false,
				"public_key":           testCAPublicKey,
			},
		})
		require.Nil(t, err)
		require.True(t, resp.IsError())
		require.Contains(t, resp.Data["error"].(string), "only one of public_key and private_key set")
	})

	t.Run("GenerateSigningKeyTrue", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]interface{}{
				"generate_signing_key": true,
			},
		})
		require.Nil(t, err)
		require.False(t, resp.IsError())
		require.NotEmpty(t, resp.Data["issuer_id"].(string))
		require.Contains(t, resp.Data["public_key"].(string), "ssh-rsa")
	})

	t.Run("GenerateSigningKeyTrueAndKeyMaterial", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Storage:   s,
			Data: map[string]interface{}{
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
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
		Data: map[string]interface{}{
			"set_as_default": true,
		},
		Storage: s,
	}
	resp, err := b.HandleRequest(context.Background(), createCaIssuerReq)
	require.NoError(t, err, "cannot submit CA issuer as default")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response submitting CA issuer as default")

	// override existing 'default with 'config/ca' endpoint
	configDefaultCARequest := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Data: map[string]interface{}{
			"private_key": testCAPrivateKey,
			"public_key":  testCAPublicKey,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), configDefaultCARequest)
	require.NoError(t, err, "cannot submit a new CA and override existing 'default'")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response submitting new CA")

	// read the 'default' issuer
	readDefaultIssuerRequest := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/ca",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), readDefaultIssuerRequest)
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
	caReq.Data = map[string]interface{}{
		"generate_signing_key": true,
		"key_type":             keyType,
		"key_bits":             keyBits,
	}
	resp, err := b.HandleRequest(context.Background(), caReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)
	require.Contains(t, resp.Data["public_key"].(string), caReq.Data["key_type"].(string), "bad case %v: expected public key of type %v but was %v", index, caReq.Data["key_type"], resp.Data["public_key"])

	issueOptions := map[string]interface{}{
		"public_key":       testCAPublicKeyEd25519,
		"valid_principals": "toor",
	}
	issueReq := &logical.Request{
		Path:      "sign/ca-issuance",
		Operation: logical.UpdateOperation,
		Data:      issueOptions,
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), issueReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)

	// Delete the configured keys
	caReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(context.Background(), caReq)
	require.NoError(t, err, "bad case %v", index)
	require.False(t, resp != nil && resp.IsError(), "bad case %v", index)
}
