// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

func transitImportTestFile(t *testing.T, material []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, material, 0o600))
	return "@" + path
}

func TestReadTransitImportKey(t *testing.T) {
	t.Parallel()
	// Include NUL and whitespace-valued bytes at both ends of binary input.
	raw := append([]byte{0, '\n', '\t', ' '}, bytes.Repeat([]byte{0xff}, 24)...)
	raw = append(raw, ' ', '\t', '\r', '\n')
	encoded := base64.StdEncoding.EncodeToString(raw)
	for _, format := range []string{"base64", "raw"} {
		t.Run(format, func(t *testing.T) {
			material := raw
			if format == "base64" {
				material = []byte(encoded + "\r\n")
			}
			key, err := readTransitImportKey(transitImportTestFile(t, material), format)
			require.NoError(t, err)
			require.Equal(t, raw, key)
		})
	}
	key, err := readTransitImportKey(encoded, "base64")
	require.NoError(t, err)
	require.Equal(t, raw, key)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		key  any
		typ  string
		der  []byte
	}{
		{"pkcs8-rsa", rsaKey, "PRIVATE KEY", nil},
		{"pkcs1-rsa", rsaKey, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"pkcs8-ec", ecKey, "PRIVATE KEY", nil},
		{"sec1-ec", ecKey, "EC PRIVATE KEY", ecDER},
		{"pkcs8-ed25519", edKey, "PRIVATE KEY", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := x509.MarshalPKCS8PrivateKey(tc.key)
			require.NoError(t, err)
			der := tc.der
			if der == nil {
				der = want
			}
			material := pem.EncodeToMemory(&pem.Block{Type: tc.typ, Bytes: der})
			material = append([]byte(" \r\n"), material...)
			material = append(material, '\t', '\n')
			got, err := readTransitImportKey(transitImportTestFile(t, material), "pem")
			require.NoError(t, err)
			require.Equal(t, want, got)
			got, err = readTransitImportKey(transitImportTestFile(t, want), "raw")
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestTransitImportInvalidKeyMaterial(t *testing.T) {
	t.Parallel()
	const marker = "SYNTHETIC-SECRET-MARKER"
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	valid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pemBlock := func(typ string, data []byte, headers map[string]string) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data, Headers: headers})
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	config := api.DefaultConfig()
	config.Address = server.URL
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetMaxRetries(0)

	for _, tc := range []struct {
		name, format string
		material     []byte
		inline       bool
		want         string
	}{
		{"empty-argument", "base64", nil, true, "must not be empty"},
		{"empty-file", "raw", nil, false, "must not be empty"},
		{"empty-base64", "base64", []byte("\r\n"), false, "must not be empty"},
		{"invalid-base64", "base64", []byte(marker), false, "base64 decoding"},
		{"unknown-format", marker, []byte(marker), true, "invalid key format"},
		{"inline-raw", "raw", []byte(marker), true, "require @path"},
		{"inline-pem", "pem", []byte(marker), true, "require @path"},
		{"not-pem", "pem", []byte(marker), false, "exactly one"},
		{"leading-text", "pem", append([]byte(marker), valid...), false, "exactly one"},
		{"trailing-text", "pem", append(bytes.Clone(valid), []byte(marker)...), false, "exactly one"},
		{"multiple-blocks", "pem", append(bytes.Clone(valid), valid...), false, "exactly one"},
		{"skipped-malformed-block", "pem", append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n"), valid...), false, "exactly one"},
		{"malformed-block", "pem", []byte("-----BEGIN PRIVATE KEY-----\n" + marker), false, "exactly one"},
		{"encrypted-pkcs8", "pem", pemBlock("ENCRYPTED PRIVATE KEY", der, nil), false, "encrypted PEM"},
		{"legacy-encrypted", "pem", pemBlock("RSA PRIVATE KEY", der, map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": marker}), false, "encrypted PEM"},
		{"headers", "pem", pemBlock("PRIVATE KEY", der, map[string]string{"Comment": marker}), false, "PEM headers"},
		{"unsupported-type", "pem", pemBlock(marker, der, nil), false, "unsupported PEM block"},
		{"invalid-der", "pem", pemBlock("PRIVATE KEY", []byte(marker), nil), false, "invalid private-key DER"},
		{"trailing-der", "pem", pemBlock("PRIVATE KEY", append(bytes.Clone(der), 0), nil), false, "invalid private-key DER"},
		{"wrong-key-type", "pem", pemBlock("RSA PRIVATE KEY", der, nil), false, "invalid private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := string(tc.material)
			if !tc.inline {
				source = transitImportTestFile(t, tc.material)
			}
			for _, method := range []string{"import", "import-version"} {
				stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
				code := RunCustom([]string{"transit", method, "-key-format=" + tc.format, "transit/keys/test", source}, &RunOptions{
					Stdout: stdout, Stderr: stderr, Client: client,
				})
				require.Equal(t, 1, code, stderr.String())
				require.Contains(t, stderr.String(), tc.want)
				require.NotContains(t, stdout.String()+stderr.String(), marker)
			}
		})
	}
	require.Zero(t, requests.Load(), "invalid local input must not contact the server")
	_, err = readTransitImportKey("@"+filepath.Join(t.TempDir(), "missing"), "raw")
	require.ErrorContains(t, err, "error reading key material file")
}

func TestTransitImportKeyFormats(t *testing.T) {
	t.Parallel()
	client, closer := testVaultServer(t)
	defer closer()
	require.NoError(t, client.Sys().Mount("transit", &api.MountInput{Type: "transit"}))
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	aesKey := bytes.Repeat([]byte{0x42}, 32)
	copy(aesKey[28:], []byte(" \t\r\n"))

	for _, tc := range []struct {
		name, format, typ, exportType string
		material, want                []byte
	}{
		{"base64-file", "base64", "aes256-gcm96", "encryption-key", []byte(base64.StdEncoding.EncodeToString(aesKey) + "\n"), aesKey},
		{"raw-aes", "raw", "aes256-gcm96", "encryption-key", aesKey, aesKey},
		{"raw-rsa-der", "raw", "rsa-2048", "encryption-key", rsaDER, rsaDER},
		{"pem-pkcs8", "pem", "rsa-2048", "encryption-key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), rsaDER},
		{"pem-pkcs1", "pem", "rsa-2048", "encryption-key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), rsaDER},
		{"pem-sec1", "pem", "ecdsa-p256", "signing-key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), ecPKCS8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := transitImportTestFile(t, tc.material)
			updatedSource, updatedWant := source, tc.want
			if tc.typ == "aes256-gcm96" {
				updatedWant = bytes.Clone(tc.want)
				updatedWant[0] ^= 0xff
				material := updatedWant
				if tc.format == "base64" {
					material = []byte(base64.StdEncoding.EncodeToString(updatedWant))
				}
				updatedSource = transitImportTestFile(t, material)
			}
			path := "transit/keys/" + tc.name
			for i, method := range []string{"import", "import", "import-version"} {
				if i > 0 {
					source = updatedSource
				}
				stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
				args := []string{"transit", method}
				if tc.format != "base64" {
					args = append(args, "-key-format="+tc.format)
				}
				args = append(args, path, source, "type="+tc.typ, "exportable=true")
				code := RunCustom(args, &RunOptions{Stdout: stdout, Stderr: stderr, Client: client})
				if i == 1 {
					require.Equal(t, 3, code, stderr.String())
				} else {
					require.Zero(t, code, stderr.String())
				}
				query := map[string][]string{}
				if tc.typ != "aes256-gcm96" {
					query["format"] = []string{"der"}
				}
				secret, err := client.Logical().ReadWithData("transit/export/"+tc.exportType+"/"+tc.name, query)
				require.NoError(t, err)
				require.NotNil(t, secret)
				keys := secret.Data["keys"].(map[string]any)
				versions := 1
				if method == "import-version" {
					versions = 2
				}
				require.Len(t, keys, versions)
				for version := 1; version <= versions; version++ {
					got, err := base64.StdEncoding.DecodeString(keys[fmt.Sprint(version)].(string))
					require.NoError(t, err)
					want := tc.want
					if version == 2 {
						want = updatedWant
					}
					require.Equal(t, want, got)
				}
			}
		})
	}
}
