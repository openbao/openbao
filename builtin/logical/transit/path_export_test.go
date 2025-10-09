// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/logical/pki"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestTransit_Export_KeyVersion_ExportsCorrectVersion(t *testing.T) {
	verifyExportsCorrectVersion(t, "encryption-key", "aes128-gcm96")
	verifyExportsCorrectVersion(t, "encryption-key", "aes256-gcm96")
	verifyExportsCorrectVersion(t, "encryption-key", "chacha20-poly1305")
	verifyExportsCorrectVersion(t, "encryption-key", "xchacha20-poly1305")
	verifyExportsCorrectVersion(t, "encryption-key", "rsa-2048")
	verifyExportsCorrectVersion(t, "encryption-key", "rsa-3072")
	verifyExportsCorrectVersion(t, "encryption-key", "rsa-4096")
	verifyExportsCorrectVersion(t, "signing-key", "ecdsa-p256")
	verifyExportsCorrectVersion(t, "signing-key", "ecdsa-p384")
	verifyExportsCorrectVersion(t, "signing-key", "ecdsa-p521")
	verifyExportsCorrectVersion(t, "signing-key", "ed25519")
	verifyExportsCorrectVersion(t, "hmac-key", "aes128-gcm96")
	verifyExportsCorrectVersion(t, "hmac-key", "aes256-gcm96")
	verifyExportsCorrectVersion(t, "hmac-key", "chacha20-poly1305")
	verifyExportsCorrectVersion(t, "hmac-key", "xchacha20-poly1305")
	verifyExportsCorrectVersion(t, "hmac-key", "ecdsa-p256")
	verifyExportsCorrectVersion(t, "hmac-key", "ecdsa-p384")
	verifyExportsCorrectVersion(t, "hmac-key", "ecdsa-p521")
	verifyExportsCorrectVersion(t, "hmac-key", "ed25519")
	verifyExportsCorrectVersion(t, "hmac-key", "hmac")
}

func verifyExportsCorrectVersion(t *testing.T, exportType, keyType string) {
	b, storage := createBackendWithSysView(t)

	// First create a key, v1
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
		"type":       keyType,
	}
	if keyType == "hmac" {
		req.Data["key_size"] = 32
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	verifyVersion := func(versionRequest string, expectedVersion int) {
		req := &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("export/%s/foo/%s", exportType, versionRequest),
		}
		rsp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		typRaw, ok := rsp.Data["type"]
		if !ok {
			t.Fatal("no type returned from export")
		}
		typ, ok := typRaw.(string)
		if !ok {
			t.Fatalf("could not find key type, resp data is %#v", rsp.Data)
		}
		if typ != keyType {
			t.Fatalf("key type mismatch; %q vs %q", typ, keyType)
		}

		keysRaw, ok := rsp.Data["keys"]
		if !ok {
			t.Fatal("could not find keys value")
		}
		keys, ok := keysRaw.(map[string]string)
		if !ok {
			t.Fatal("could not cast to keys map")
		}
		if len(keys) != 1 {
			t.Fatal("unexpected number of keys found")
		}

		for k := range keys {
			if k != strconv.Itoa(expectedVersion) {
				t.Fatalf("expected version %q, received version %q", strconv.Itoa(expectedVersion), k)
			}
		}
	}

	verifyVersion("v1", 1)
	verifyVersion("1", 1)
	verifyVersion("latest", 1)

	req.Path = "keys/foo/rotate"
	// v2
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	verifyVersion("v1", 1)
	verifyVersion("1", 1)
	verifyVersion("v2", 2)
	verifyVersion("2", 2)
	verifyVersion("latest", 2)

	// v3
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	verifyVersion("v1", 1)
	verifyVersion("1", 1)
	verifyVersion("v3", 3)
	verifyVersion("3", 3)
	verifyVersion("latest", 3)
}

func TestTransit_Export_ValidVersionsOnly(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// First create a key, v1
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req.Path = "keys/foo/rotate"
	// v2
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// v3
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	verifyExport := func(validVersions []int) {
		req = &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "export/encryption-key/foo",
		}
		rsp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := rsp.Data["keys"]; !ok {
			t.Error("no keys returned from export")
		}

		keys, ok := rsp.Data["keys"].(map[string]string)
		if !ok {
			t.Error("could not cast to keys object")
		}
		if len(keys) != len(validVersions) {
			t.Errorf("expected %d key count, received %d", len(validVersions), len(keys))
		}
		for _, version := range validVersions {
			if _, ok := keys[strconv.Itoa(version)]; !ok {
				t.Errorf("expecting to find key version %d, not found", version)
			}
		}
	}

	verifyExport([]int{1, 2, 3})

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo/config",
	}
	req.Data = map[string]interface{}{
		"min_decryption_version": 3,
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	verifyExport([]int{3})

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo/config",
	}
	req.Data = map[string]interface{}{
		"min_decryption_version": 2,
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	verifyExport([]int{2, 3})

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo/rotate",
	}
	// v4
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	verifyExport([]int{2, 3, 4})
}

func TestTransit_Export_KeysNotMarkedExportable_ReturnsError(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": false,
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/encryption-key/foo",
	}
	rsp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !rsp.IsError() {
		t.Fatal("Key not marked as exportable but was exported.")
	}
}

func TestTransit_Export_SigningDoesNotSupportSigning_ReturnsError(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
		"type":       "aes256-gcm96",
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/signing-key/foo",
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Key does not support signing but was exported without error.")
	}
}

func TestTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t *testing.T) {
	testTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t, "ecdsa-p256")
	testTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t, "ecdsa-p384")
	testTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t, "ecdsa-p521")
	testTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t, "ed25519")
}

func testTransit_Export_EncryptionDoesNotSupportEncryption_ReturnsError(t *testing.T, keyType string) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
		"type":       keyType,
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/encryption-key/foo",
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("Key %s does not support encryption but was exported without error.", keyType)
	}
}

func TestTransit_Export_KeysDoesNotExist_ReturnsNotFound(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/encryption-key/foo",
	}
	rsp, err := b.HandleRequest(context.Background(), req)

	if rsp != nil || err != nil {
		t.Fatal("Key does not exist but does not return not found")
	}
}

func TestTransit_Export_EncryptionKey_DoesNotExportHMACKey(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
		"type":       "aes256-gcm96",
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	req = &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "export/encryption-key/foo",
	}
	encryptionKeyRsp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Path = "export/hmac-key/foo"
	hmacKeyRsp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	encryptionKeys, ok := encryptionKeyRsp.Data["keys"].(map[string]string)
	if !ok {
		t.Error("could not cast to keys object")
	}
	hmacKeys, ok := hmacKeyRsp.Data["keys"].(map[string]string)
	if !ok {
		t.Error("could not cast to keys object")
	}
	if len(hmacKeys) != len(encryptionKeys) {
		t.Errorf("hmac (%d) and encryption (%d) key count don't match",
			len(hmacKeys), len(encryptionKeys))
	}

	if reflect.DeepEqual(encryptionKeyRsp.Data, hmacKeyRsp.Data) {
		t.Fatal("Encryption key data matched hmac key data")
	}
}

func TestTransit_Export_CorrectFormat(t *testing.T) {
	verifyExportsCorrectFormat(t, "encryption-key", "aes128-gcm96")
	verifyExportsCorrectFormat(t, "encryption-key", "aes256-gcm96")
	verifyExportsCorrectFormat(t, "encryption-key", "chacha20-poly1305")
	verifyExportsCorrectFormat(t, "encryption-key", "xchacha20-poly1305")
	verifyExportsCorrectFormat(t, "encryption-key", "rsa-2048")
	verifyExportsCorrectFormat(t, "encryption-key", "rsa-3072")
	verifyExportsCorrectFormat(t, "encryption-key", "rsa-4096")
	verifyExportsCorrectFormat(t, "signing-key", "ecdsa-p256")
	verifyExportsCorrectFormat(t, "signing-key", "ecdsa-p384")
	verifyExportsCorrectFormat(t, "signing-key", "ecdsa-p521")
	verifyExportsCorrectFormat(t, "signing-key", "ed25519")
	verifyExportsCorrectFormat(t, "signing-key", "rsa-2048")
	verifyExportsCorrectFormat(t, "signing-key", "rsa-3072")
	verifyExportsCorrectFormat(t, "signing-key", "rsa-4096")
	verifyExportsCorrectFormat(t, "public-key", "ecdsa-p256")
	verifyExportsCorrectFormat(t, "public-key", "ecdsa-p384")
	verifyExportsCorrectFormat(t, "public-key", "ecdsa-p521")
	verifyExportsCorrectFormat(t, "public-key", "ed25519")
	verifyExportsCorrectFormat(t, "public-key", "rsa-2048")
	verifyExportsCorrectFormat(t, "public-key", "rsa-3072")
	verifyExportsCorrectFormat(t, "public-key", "rsa-4096")
	verifyExportsCorrectFormat(t, "hmac-key", "aes128-gcm96")
	verifyExportsCorrectFormat(t, "hmac-key", "aes256-gcm96")
	verifyExportsCorrectFormat(t, "hmac-key", "chacha20-poly1305")
	verifyExportsCorrectFormat(t, "hmac-key", "xchacha20-poly1305")
	verifyExportsCorrectFormat(t, "hmac-key", "ecdsa-p256")
	verifyExportsCorrectFormat(t, "hmac-key", "ecdsa-p384")
	verifyExportsCorrectFormat(t, "hmac-key", "ecdsa-p521")
	verifyExportsCorrectFormat(t, "hmac-key", "rsa-2048")
	verifyExportsCorrectFormat(t, "hmac-key", "rsa-3072")
	verifyExportsCorrectFormat(t, "hmac-key", "rsa-4096")
	verifyExportsCorrectFormat(t, "hmac-key", "ed25519")
	verifyExportsCorrectFormat(t, "hmac-key", "hmac")
}

func verifyExportsCorrectFormat(t *testing.T, exportType, keyType string) {
	b, storage := createBackendWithSysView(t)

	// First create a key
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	req.Data = map[string]interface{}{
		"exportable": true,
		"type":       keyType,
	}
	if keyType == "hmac" {
		req.Data["key_size"] = 32
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	verifyFormat := func(formatRequest string) {
		t.Logf("handling key: %v / %v / %v", exportType, keyType, formatRequest)

		req := &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("export/%s/foo", exportType),
			Data: map[string]interface{}{
				"format": formatRequest,
			},
		}

		rsp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("on req to %v: %v", req.Path, err)
		}

		keysRaw, ok := rsp.Data["keys"]
		if !ok {
			t.Fatal("could not find keys value")
		}
		keys, ok := keysRaw.(map[string]string)
		if !ok {
			t.Fatal("could not cast to keys map")
		}
		if len(keys) != 1 {
			t.Fatal("unexpected number of keys found")
		}

		for _, k := range keys {
			if exportType != "hmac-key" && formatRequest == "" && (strings.HasPrefix(keyType, "rsa") || strings.HasPrefix(keyType, "ecdsa")) {
				block, rest := pem.Decode([]byte(k))
				if len(strings.TrimSpace(string(rest))) > 0 {
					t.Fatalf("remainder when decoding raw %v key (%v): block=%v rest=%v", keyType, k, block, rest)
				}

				if block == nil {
					t.Fatalf("no pem block when decoding raw %v key (%v): block=%v rest=%v", keyType, k, block, rest)
				}

				if exportType == "public-key" {
					if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
						t.Fatalf("failed to parse raw rsa key (%v): %v", k, err)
					}
				} else if strings.HasPrefix(keyType, "rsa") {
					if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
						t.Fatalf("failed to parse raw rsa key (%v): %v", k, err)
					}
				} else {
					if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
						t.Fatalf("failed to parse raw ec key (%v): %v", k, err)
					}
				}
			} else if formatRequest == "" && strings.HasPrefix(keyType, "ec") {
			} else if formatRequest == "der" || formatRequest == "pem" {
				var keyData []byte
				var err error

				if formatRequest == "der" {
					keyData, err = base64.StdEncoding.DecodeString(k)
					if err != nil {
						t.Fatalf("error decoding der key (%v): %v", k, err)
					}
				} else {
					block, rest := pem.Decode([]byte(k))
					if len(strings.TrimSpace(string(rest))) > 0 {
						t.Fatalf("remainder when decoding pem key (%v): block=%v rest=%v", k, block, rest)
					}

					if block == nil {
						t.Fatalf("no pem block when decoding pem key (%v): block=%v rest=%v", k, block, rest)
					}

					keyData = block.Bytes
				}

				if exportType == "public-key" {
					_, err := x509.ParsePKIXPublicKey(keyData)
					if err != nil {
						t.Fatalf("error decoding `%v` key (%v): %v", formatRequest, k, err)
					}
				} else {
					_, err := x509.ParsePKCS8PrivateKey(keyData)
					if err != nil {
						t.Fatalf("error decoding `%v` key (%v): %v", formatRequest, k, err)
					}
				}
			} else {
				if _, err := base64.StdEncoding.DecodeString(k); err != nil {
					t.Fatalf("error decoding raw key (%v / %v): %v", formatRequest, keyType, k)
				}
			}
		}
	}

	verifyFormat("")
	if exportType == "hmac-key" || strings.Contains(keyType, "aes") || strings.Contains(keyType, "chacha20") || keyType == "hmac" {
		verifyFormat("raw")
	} else if keyType == "ed25519" {
		verifyFormat("raw")
		verifyFormat("der")
		verifyFormat("pem")
	} else {
		verifyFormat("der")
		verifyFormat("pem")
	}
}

func TestTransit_Export_CertificateChain(t *testing.T) {
	generateKeys(t)

	// create Cluster
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": Factory,
			"pki":     pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// mount transit backend
	err := client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)

	// mount PKI backend
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	require.NoError(t, err)

	t.Parallel()
	testTransit_Export_CertificateChain(t, client, "rsa-2048")
	testTransit_Export_CertificateChain(t, client, "rsa-3072")
	testTransit_Export_CertificateChain(t, client, "rsa-4096")
	testTransit_Export_CertificateChain(t, client, "ecdsa-p256")
	testTransit_Export_CertificateChain(t, client, "ecdsa-p384")
	testTransit_Export_CertificateChain(t, client, "ecdsa-p521")
	testTransit_Export_CertificateChain(t, client, "ed25519")
}

func testTransit_Export_CertificateChain(t *testing.T, apiClient *api.Client, keyType string) {
	keyName := fmt.Sprintf("%s", keyType)
	issuerName := fmt.Sprintf("%s-issuer", keyType)

	// get key to be imported
	privKey := getKey(t, keyType)
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err, fmt.Sprintf("failed to marshal private key: %s", err))

	// create CSR
	var csrTemplate x509.CertificateRequest
	csrTemplate.Subject.CommonName = "example.com"
	csrBytes, err := x509.CreateCertificateRequest(cryptoRand.Reader, &csrTemplate, privKey)
	require.NoError(t, err, fmt.Sprintf("failed to create CSR: %s", err))

	pemCsr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))

	// generate PKI root
	_, err = apiClient.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"issuer_name": issuerName,
		"common_name": "PKI Root X1",
	})
	require.NoError(t, err)

	// create role to be used in the certificate issuing
	_, err = apiClient.Logical().Write("pki/roles/example-dot-com", map[string]interface{}{
		"issuer_ref":                         issuerName,
		"allowed_domains":                    "example.com",
		"allow_bare_domains":                 true,
		"basic_constraints_valid_for_non_ca": true,
		"key_type":                           "any",
	})
	require.NoError(t, err)

	// sign the CSR
	resp, err := apiClient.Logical().Write("pki/sign/example-dot-com", map[string]interface{}{
		"issuer_ref": issuerName,
		"csr":        pemCsr,
		"ttl":        "10m",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	leafCertPEM := resp.Data["certificate"].(string)

	// get wrapping key
	resp, err = apiClient.Logical().Read("transit/wrapping_key")
	require.NoError(t, err)
	require.NotNil(t, resp)

	pubWrappingKeyString := strings.TrimSpace(resp.Data["public_key"].(string))
	wrappingKeyPemBlock, _ := pem.Decode([]byte(pubWrappingKeyString))

	pubWrappingKey, err := x509.ParsePKIXPublicKey(wrappingKeyPemBlock.Bytes)
	require.NoError(t, err, "failed to parse wrapping key")

	blob := wrapTargetPKCS8ForImport(t, pubWrappingKey.(*rsa.PublicKey), privKeyBytes, "SHA256")

	// import key
	_, err = apiClient.Logical().Write(fmt.Sprintf("/transit/keys/%s/import", keyName), map[string]interface{}{
		"ciphertext": blob,
		"type":       keyType,
	})
	require.NoError(t, err)

	_, err = apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/set-certificate", keyName), map[string]interface{}{
		"certificate_chain": leafCertPEM,
	})
	require.NoError(t, err)

	// export cert chain
	resp, err = apiClient.Logical().Read(fmt.Sprintf("transit/export/certificate-chain/%s", keyName))
	require.NoError(t, err)
	require.NotNil(t, resp)

	exportedKeys := resp.Data["keys"].(map[string]interface{})
	exportedCertChainPEM := exportedKeys["1"].(string)

	if exportedCertChainPEM != leafCertPEM {
		t.Fatal("expected exported cert chain to match with imported value")
	}
}
