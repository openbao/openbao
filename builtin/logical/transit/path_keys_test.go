// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/builtin/audit/file"
	"github.com/openbao/openbao/command/server"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestTransit_Issue_2958(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		RawConfig: &server.Config{
			UnsafeAllowAPIAuditCreation: true,
		},
		LogicalBackends: map[string]logical.Factory{
			"transit": Factory,
		},
		AuditBackends: map[string]audit.Factory{
			"file": file.Factory,
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

	err := client.Sys().EnableAuditWithOptions("file", &api.EnableAuditOptions{
		Type: "file",
		Options: map[string]string{
			"file_path": "/dev/null",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("transit/keys/foo", map[string]interface{}{
		"type": "ecdsa-p256",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("transit/keys/foobar", map[string]interface{}{
		"type": "ecdsa-p384",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("transit/keys/bar", map[string]interface{}{
		"type": "ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Read("transit/keys/foo")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Read("transit/keys/foobar")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Read("transit/keys/bar")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTransit_CreateKeyWithAutorotation(t *testing.T) {
	tests := map[string]struct {
		autoRotatePeriod interface{}
		shouldError      bool
		expectedValue    time.Duration
	}{
		"default (no value)": {
			shouldError: false,
		},
		"0 (int)": {
			autoRotatePeriod: 0,
			shouldError:      false,
			expectedValue:    0,
		},
		"0 (string)": {
			autoRotatePeriod: "0",
			shouldError:      false,
			expectedValue:    0,
		},
		"5 seconds": {
			autoRotatePeriod: "5s",
			shouldError:      true,
		},
		"5 hours": {
			autoRotatePeriod: "5h",
			shouldError:      false,
			expectedValue:    5 * time.Hour,
		},
		"negative value": {
			autoRotatePeriod: "-1800s",
			shouldError:      true,
		},
		"invalid string": {
			autoRotatePeriod: "this shouldn't work",
			shouldError:      true,
		},
	}

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": Factory,
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
	err := client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			keyNameBytes, err := uuid.GenerateRandomBytes(16)
			if err != nil {
				t.Fatal(err)
			}
			keyName := hex.EncodeToString(keyNameBytes)

			_, err = client.Logical().Write(fmt.Sprintf("transit/keys/%s", keyName), map[string]interface{}{
				"auto_rotate_period": test.autoRotatePeriod,
			})
			switch {
			case test.shouldError && err == nil:
				t.Fatal("expected non-nil error")
			case !test.shouldError && err != nil:
				t.Fatal(err)
			}

			if !test.shouldError {
				resp, err := client.Logical().Read(fmt.Sprintf("transit/keys/%s", keyName))
				if err != nil {
					t.Fatal(err)
				}
				if resp == nil {
					t.Fatal("expected non-nil response")
				}
				gotRaw, ok := resp.Data["auto_rotate_period"].(json.Number)
				if !ok {
					t.Fatal("returned value is of unexpected type")
				}
				got, err := gotRaw.Int64()
				if err != nil {
					t.Fatal(err)
				}
				want := int64(test.expectedValue.Seconds())
				if got != want {
					t.Fatalf("incorrect auto_rotate_period returned, got: %d, want: %d", got, want)
				}
			}
		})
	}
}

func TestOpsFailAfterDeletion(t *testing.T) {
	t.Parallel()

	testOpsFailAfterDeletion(t, "aes128-gcm96", true, false)
	testOpsFailAfterDeletion(t, "aes256-gcm96", true, false)
	testOpsFailAfterDeletion(t, "chacha20-poly1305", true, false)
	testOpsFailAfterDeletion(t, "xchacha20-poly1305", true, false)
	testOpsFailAfterDeletion(t, "rsa-2048", true, true)
	testOpsFailAfterDeletion(t, "rsa-3072", true, true)
	testOpsFailAfterDeletion(t, "rsa-4096", true, true)
}

func testOpsFailAfterDeletion(t *testing.T, keyType string, encrypt bool, sign bool) {
	b, s := createBackendWithStorage(t)

	// Create a key
	req := &logical.Request{
		Path:      "keys/test",
		Operation: logical.UpdateOperation,
		Storage:   s,
		Data: map[string]interface{}{
			"type":       keyType,
			"exportable": true,
		},
	}
	if keyType == "hmac" {
		req.Data["key_size"] = 32
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Now create a wrapping key for BYOK
	req.Path = "keys/byok-key"
	req.Data = map[string]interface{}{
		"type": "rsa-4096",
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Validate ops work with the key.
	validateOpsFail(t, b, s, encrypt, sign, false)

	// Mark the key as soft deleted
	req.Path = "keys/test/soft-delete"
	req.Operation = logical.DeleteOperation
	req.Data = nil

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Validate ops fail with the key now.
	validateOpsFail(t, b, s, encrypt, sign, true)

	// Restore the key.
	req.Path = "keys/test/soft-delete-restore"
	req.Operation = logical.UpdateOperation

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Validate ops work with the key.
	validateOpsFail(t, b, s, encrypt, sign, false)
}

func validateOpsFail(t *testing.T, b *backend, s logical.Storage, encrypt bool, sign bool, expectedFailure bool) {
	// Reading a key should always succeed
	req := &logical.Request{
		Path:      "keys/test",
		Operation: logical.ReadOperation,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	req.Operation = logical.UpdateOperation

	if encrypt {
		// Encryption operations should succeed conditionally.
		req.Path = "encrypt/test"
		req.Data = map[string]interface{}{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("hello world")),
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if expectedFailure {
			require.Error(t, err)
			resp = &logical.Response{
				Data: map[string]interface{}{},
			}
		} else {
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Contains(t, resp.Data, "ciphertext")
			require.NotNil(t, resp.Data["ciphertext"])
		}

		req.Path = "decrypt/test"
		req.Data = map[string]interface{}{
			"ciphertext": resp.Data["ciphertext"],
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if expectedFailure {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Contains(t, resp.Data, "plaintext")
			require.NotNil(t, resp.Data["plaintext"])
		}
	}

	if sign {
		// Signature operations should succeed conditionally.
		req.Path = "sign/test"
		req.Data = map[string]interface{}{
			"input": base64.StdEncoding.EncodeToString([]byte("hello world")),
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if expectedFailure {
			require.Error(t, err)
			resp = &logical.Response{
				Data: map[string]interface{}{},
			}
		} else {
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Contains(t, resp.Data, "signature")
			require.NotNil(t, resp.Data["signature"])
		}

		req.Path = "verify/test"
		req.Data = map[string]interface{}{
			"input":     base64.StdEncoding.EncodeToString([]byte("hello world")),
			"signature": resp.Data["signature"],
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if expectedFailure {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Contains(t, resp.Data, "valid")
			require.NotNil(t, resp.Data["valid"])
		}
	}

	// HMAC operations should succeed conditionally.
	req.Path = "hmac/test"
	req.Data = map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte("hello world")),
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if expectedFailure {
		require.Error(t, err)
		resp = &logical.Response{
			Data: map[string]interface{}{},
		}
	} else {
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.Data, "hmac")
		require.NotNil(t, resp.Data["hmac"])
	}

	req.Path = "verify/test"
	req.Data = map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte("hello world")),
		"hmac":  resp.Data["hmac"],
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if expectedFailure {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Contains(t, resp.Data, "valid")
		require.NotNil(t, resp.Data["valid"])
	}

	// Validate that rotation conditionally fails
	req.Path = "keys/test/rotate"
	req.Data = nil

	resp, err = b.HandleRequest(context.Background(), req)
	if expectedFailure {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	// Validate that exporting conditionally fails.
	req.Operation = logical.ReadOperation
	if encrypt {
		req.Path = "export/encryption-key/test"
	} else if sign {
		req.Path = "export/signing-key/test"
	} else {
		req.Path = "export/hmac-key/test"
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if expectedFailure {
		require.Error(t, err)
	} else {
		require.NoError(t, err, "path: %v", req.Path)
		require.NotNil(t, resp)
	}

	// Validate that BYOK exporting conditionally fails.
	req.Path = "byok-export/byok-key/test"

	resp, err = b.HandleRequest(context.Background(), req)
	if expectedFailure {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	// Soft deleted keys remain updatable.
}
