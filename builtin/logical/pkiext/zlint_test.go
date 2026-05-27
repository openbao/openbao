// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkiext

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/stretchr/testify/require"
)

func RunZLint(t *testing.T, certificate string) []byte {
	t.Helper()

	certFile := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certificate), 0o600))

	cmd := exec.Command("go", "run", "-modfile=tools/go.mod", "github.com/zmap/zlint/v3/cmd/zlint", certFile)
	_, thisFile, _, _ := runtime.Caller(0)
	cmd.Dir = filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "zlint failed: %v:\n%s", err, string(out))

	return out
}

func RunZLintRootTest(t *testing.T, keyType string, keyBits int, usePSS bool, ignored []string) {
	b, s := pki.CreateBackendWithStorage(t)

	resp, err := pki.CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name":  "Root X1",
		"country":      "US",
		"organization": "Dadgarcorp",
		"key_type":     keyType,
		"key_bits":     keyBits,
		"use_pss":      usePSS,
	})
	require.NoError(t, err)
	rootCert := resp.Data["certificate"].(string)

	var parsed map[string]interface{}
	output := RunZLint(t, rootCert)

	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("failed to parse zlint output as JSON: %v\nOutput:\n%v\n\n", err, string(output))
	}

	for key, rawValue := range parsed {
		value := rawValue.(map[string]interface{})
		result, ok := value["result"]
		if !ok || result == "NA" {
			continue
		}

		if result == "error" {
			skip := false
			for _, allowedFailures := range ignored {
				if allowedFailures == key {
					skip = true
					break
				}
			}

			if !skip {
				t.Fatalf("got unexpected error from test %v: %v", key, value)
			}
		}
	}
}

func Test_ZLintRSA2048(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "rsa", 2048, false, nil)
}

func Test_ZLintRSA2048PSS(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "rsa", 2048, true, nil)
}

func Test_ZLintRSA3072(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "rsa", 3072, false, nil)
}

func Test_ZLintRSA3072PSS(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "rsa", 3072, true, nil)
}

func Test_ZLintECDSA256(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "ec", 256, false, nil)
}

func Test_ZLintECDSA384(t *testing.T) {
	t.Parallel()
	RunZLintRootTest(t, "ec", 384, false, nil)
}

func Test_ZLintECDSA521(t *testing.T) {
	t.Parallel()
	// Mozilla doesn't allow P-521 ECDSA keys.
	RunZLintRootTest(t, "ec", 521, false, []string{
		"e_mp_ecdsa_pub_key_encoding_correct",
		"e_mp_ecdsa_signature_encoding_correct",
	})
}
