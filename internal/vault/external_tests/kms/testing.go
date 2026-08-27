// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

func ExerciseTransitKMS(t *testing.T, client *api.Client) {
	t.Run("transit", func(t *testing.T) {
		ExerciseTransitWithTransitKMS(t, client)
	})
	t.Run("pki", func(t *testing.T) {
		ExercisePKIWithTransitKMS(t, client)
	})
}

type transitKeyType struct {
	Type           string
	EncryptDecrypt bool
	SignVerify     bool
}

func knownTransitKeyTypes() []transitKeyType {
	return []transitKeyType{
		{
			Type:           "aes128-gcm96",
			EncryptDecrypt: true,
		},
		{
			Type:           "aes256-gcm96",
			EncryptDecrypt: true,
		},
		{
			Type:           "chacha20-poly1305",
			EncryptDecrypt: true,
		},
		{
			Type:           "xchacha20-poly1305",
			EncryptDecrypt: true,
		},
		{
			Type:       "ed25519",
			SignVerify: true,
		},
		{
			Type:       "ecdsa-p256",
			SignVerify: true,
		},
		{
			Type:       "ecdsa-p384",
			SignVerify: true,
		},
		{
			Type:       "ecdsa-p521",
			SignVerify: true,
		},
		{
			Type:           "rsa-2048",
			EncryptDecrypt: true,
			SignVerify:     true,
		},
		{
			Type:           "rsa-3072",
			EncryptDecrypt: true,
			SignVerify:     true,
		},
		{
			Type:           "rsa-4096",
			EncryptDecrypt: true,
			SignVerify:     true,
		},
	}
}

func SetupTransit(t *testing.T, client *api.Client) {
	err := client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)
}

func ExerciseTransitWithTransitKMS(t *testing.T, client *api.Client) {
	SetupTransit(t, client)

	keyTypes := knownTransitKeyTypes()
	for _, tc := range keyTypes {
		t.Run(tc.Type, func(t *testing.T) {
			baseName := fmt.Sprintf("transit-%v", tc.Type)

			// Set up backing key.
			keyPath := fmt.Sprintf("keys/keys/%v", baseName)
			_, err := client.Logical().Write(keyPath, map[string]any{
				"type": tc.Type,
			})
			require.NoError(t, err)

			// Set up external key.
			extKeyPath := fmt.Sprintf("sys/external-keys/configs/kms/keys/%v", baseName)
			_, err = client.Logical().Write(extKeyPath, map[string]any{
				"name":    baseName,
				"version": 1,
			})
			require.NoError(t, err)

			ExerciseTransitForKey(t, client, baseName, tc.EncryptDecrypt, tc.SignVerify)
		})
	}
}

func ExerciseTransitForKey(t *testing.T, client *api.Client, baseName string, encryptDecrypt bool, signVerify bool) {
	transitPath := fmt.Sprintf("transit/keys/%v", baseName)

	extKeyGrantPath := fmt.Sprintf("sys/external-keys/configs/kms/keys/%v/grants/transit", baseName)
	extKeyRef := fmt.Sprintf("kms:%v", baseName)

	_, err := client.Logical().Write(transitPath, map[string]any{
		"type":             "external-key",
		"external_key_ref": extKeyRef,
	})
	require.Error(t, err)

	_, err = client.Logical().Write(extKeyGrantPath, nil)
	require.NoError(t, err)

	_, err = client.Logical().Write(transitPath, map[string]any{
		"type":             "external-key",
		"external_key_ref": extKeyRef,
	})
	require.NoError(t, err)

	if encryptDecrypt {
		t.Run("encrypt-decrypt", func(t *testing.T) {
			t.Parallel()
			ExerciseTransitEncryptDecrypt(t, client, "keys", baseName)
			ExerciseTransitEncryptDecrypt(t, client, "transit", baseName)
		})
	}
	if signVerify {
		t.Run("sign-verify", func(t *testing.T) {
			t.Parallel()
			ExerciseTransitSignVerify(t, client, "keys", baseName)
			ExerciseTransitSignVerify(t, client, "transit", baseName)
		})
	}
}

func ExerciseTransitEncryptDecrypt(t *testing.T, client *api.Client, mountName string, keyName string) {
	encryptPath := fmt.Sprintf("%v/encrypt/%v", mountName, keyName)
	decryptPath := fmt.Sprintf("%v/decrypt/%v", mountName, keyName)

	plaintext, err := uuid.GenerateRandomBytes(128)
	require.NoError(t, err)
	plaintextEncoded := base64.StdEncoding.EncodeToString(plaintext)

	resp, err := client.Logical().Write(encryptPath, map[string]any{
		"plaintext": plaintextEncoded,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "ciphertext")

	ciphertext := resp.Data["ciphertext"]
	require.NotEmpty(t, ciphertext)
	require.NotEqual(t, ciphertext, plaintextEncoded)

	resp, err = client.Logical().Write(decryptPath, map[string]any{
		"ciphertext": ciphertext,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "plaintext")

	decrypted := resp.Data["plaintext"]
	require.NotEmpty(t, decrypted)
	require.Equal(t, decrypted, plaintextEncoded)
}

func ExerciseTransitSignVerify(t *testing.T, client *api.Client, mountName string, keyName string) {
	signPath := fmt.Sprintf("%v/sign/%v", mountName, keyName)
	verifyPath := fmt.Sprintf("%v/verify/%v", mountName, keyName)

	plaintext, err := uuid.GenerateRandomBytes(128)
	require.NoError(t, err)
	plaintextEncoded := base64.StdEncoding.EncodeToString(plaintext)

	resp, err := client.Logical().Write(signPath, map[string]any{
		"input":               plaintextEncoded,
		"signature_algorithm": "pss",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "signature")

	signature := resp.Data["signature"]
	require.NotEmpty(t, signature)
	require.NotEqual(t, signature, plaintextEncoded)

	resp, err = client.Logical().Write(verifyPath, map[string]any{
		"input":               plaintextEncoded,
		"signature":           signature,
		"signature_algorithm": "pss",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "valid")

	verified := resp.Data["valid"]
	require.Equal(t, verified, true)
}

func SetupPKI(t *testing.T, client *api.Client) {
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("pki/roles/testing", map[string]any{
		"allow_any_name": true,
		"use_pss":        true,
	})
	require.NoError(t, err)
}

func ExercisePKIWithTransitKMS(t *testing.T, client *api.Client) {
	SetupPKI(t, client)

	keyTypes := knownTransitKeyTypes()
	for _, tc := range keyTypes {
		if !tc.SignVerify {
			continue
		}

		t.Run(tc.Type, func(t *testing.T) {
			t.Parallel()

			baseName := fmt.Sprintf("pki-%v", tc.Type)

			// Set up backing key.
			keyPath := fmt.Sprintf("keys/keys/%v", baseName)
			_, err := client.Logical().Write(keyPath, map[string]any{
				"type": tc.Type,
			})
			require.NoError(t, err)

			// Set up external key.
			extKeyPath := fmt.Sprintf("sys/external-keys/configs/kms/keys/%v", baseName)
			_, err = client.Logical().Write(extKeyPath, map[string]any{
				"name":    baseName,
				"version": 1,
			})
			require.NoError(t, err)

			ExercisePKIForKey(t, client, baseName)
		})
	}
}

func ExercisePKIForKey(t *testing.T, client *api.Client, baseName string) {
	extKeyGrantPath := fmt.Sprintf("sys/external-keys/configs/kms/keys/%v/grants/pki", baseName)
	_, err := client.Logical().Write(extKeyGrantPath, nil)
	require.NoError(t, err)

	extKeyRef := fmt.Sprintf("kms:%v", baseName)
	t.Run("root-ca", func(t *testing.T) {
		t.Parallel()
		ExercisePKIRootCA(t, client, "pki", baseName, extKeyRef)
	})
	t.Run("int-ca", func(t *testing.T) {
		t.Parallel()
		ExercisePKIIntermediateCA(t, client, "pki", baseName, extKeyRef)
	})
}

func ExercisePKIRootCA(t *testing.T, client *api.Client, mountName string, keyName string, extKeyRef string) {
	// Generate a root CA certificate.
	issuerName := fmt.Sprintf("kms-root-%v", keyName)
	rootGeneratePath := fmt.Sprintf("%v/issuers/generate/root/kms", mountName)
	resp, err := client.Logical().Write(rootGeneratePath, map[string]any{
		"issuer_name":      issuerName,
		"common_name":      issuerName,
		"external_key_ref": extKeyRef,
		"use_pss":          true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "certificate")
	require.Contains(t, resp.Data, "key_id")

	keyId := resp.Data["key_id"]
	require.NotEmpty(t, keyId)

	// Update the key's name.
	keyPath := fmt.Sprintf("%v/key/%v", mountName, keyId)
	_, err = client.Logical().Write(keyPath, map[string]any{
		"key_name": keyName,
	})
	require.NoError(t, err)

	ExercisePKICA(t, client, mountName, issuerName)
}

func ExercisePKIIntermediateCA(t *testing.T, client *api.Client, mountName string, keyName string, extKeyRef string) {
	// Generate a root CA certificate. Make it Ed25519 for speed.
	issuerName := fmt.Sprintf("kms-int-%v", keyName)
	rootName := fmt.Sprintf("kms-int-%v-root", keyName)

	rootGeneratePath := fmt.Sprintf("%v/issuers/generate/root/internal", mountName)
	resp, err := client.Logical().Write(rootGeneratePath, map[string]any{
		"issuer_name": rootName,
		"common_name": rootName,
		"key_type":    "ed25519",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "certificate")
	require.Contains(t, resp.Data, "key_id")

	keyId := resp.Data["key_id"]
	require.NotEmpty(t, keyId)

	// Update the root key's name.
	keyPath := fmt.Sprintf("%v/key/%v", mountName, keyId)
	rootKeyName := fmt.Sprintf("%v-root", keyName)
	_, err = client.Logical().Write(keyPath, map[string]any{
		"key_name": rootKeyName,
	})
	require.NoError(t, err)

	// Create an intermediate CA certificate.
	intGeneratePath := fmt.Sprintf("%v/issuers/generate/intermediate/kms", mountName)
	resp, err = client.Logical().Write(intGeneratePath, map[string]any{
		"common_name":      rootName,
		"external_key_ref": extKeyRef,
		"use_pss":          true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "csr")
	require.Contains(t, resp.Data, "key_id")

	keyId = resp.Data["key_id"]
	require.NotEmpty(t, keyId)

	csr := resp.Data["csr"]
	require.NotEmpty(t, csr)

	// Update the intermediate key's name.
	keyPath = fmt.Sprintf("%v/key/%v", mountName, keyId)
	_, err = client.Logical().Write(keyPath, map[string]any{
		"key_name": keyName,
	})
	require.NoError(t, err)

	// Sign the intermediate CA's certificate.
	intSignPath := fmt.Sprintf("%v/issuer/%v/sign-intermediate", mountName, rootName)
	resp, err = client.Logical().Write(intSignPath, map[string]any{
		"csr":     csr,
		"use_pss": true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "certificate")
	intCert := resp.Data["certificate"]
	require.NotEmpty(t, intCert)

	// Import the intermediate certificate.
	intImportPath := fmt.Sprintf("%v/issuers/import/cert", mountName)
	resp, err = client.Logical().Write(intImportPath, map[string]any{
		"pem_bundle": intCert,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "imported_issuers")
	require.Len(t, resp.Data["imported_issuers"], 1)
	importedId := resp.Data["imported_issuers"].([]any)

	// Set the name of the imported issuer.
	issuerPath := fmt.Sprintf("%v/issuer/%v", mountName, importedId[0])
	_, err = client.Logical().JSONMergePatch(t.Context(), issuerPath, map[string]any{
		"issuer_name": issuerName,
	})
	require.NoError(t, err)

	// Set the imported certificate as default.

	ExercisePKICA(t, client, mountName, issuerName)
}

func ExercisePKICA(t *testing.T, client *api.Client, mountName string, issuerName string) {
	// Ensure we can issue leaf certificates using this issuer.
	leafIssuePath := fmt.Sprintf("%v/issuer/%v/issue/testing", mountName, issuerName)
	resp, err := client.Logical().Write(leafIssuePath, map[string]any{
		"common_name": "openbao.org",
		"ttl":         "900s",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "certificate")
	require.Contains(t, resp.Data, "serial_number")

	leafCert := resp.Data["certificate"]
	require.NotEmpty(t, leafCert)

	leafSerial := resp.Data["serial_number"]
	require.NotEmpty(t, leafSerial)

	// Ensure we can revoke certificates using this issuer.
	revokePath := fmt.Sprintf("%v/revoke", mountName)
	resp, err = client.Logical().Write(revokePath, map[string]any{
		"serial_number": leafSerial,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "revocation_time")

	// Ensure we can rotate the CRL.
	crlRotatePath := fmt.Sprintf("%v/crl/rotate", mountName)
	_, err = client.Logical().Read(crlRotatePath)
	require.NoError(t, err)

	// Ensure we can read this issuer's CRL.
	issuerCrlPath := fmt.Sprintf("%v/issuer/%v/crl", mountName, issuerName)
	resp, err = client.Logical().Read(issuerCrlPath)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.Contains(t, resp.Data, "crl")
}
