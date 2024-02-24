// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestNewVaultWriteQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		d    map[string]interface{}
		exp  *VaultWriteQuery
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			nil,
			true,
		},
		{
			"path",
			"path",
			nil,
			&VaultWriteQuery{
				path:     "path",
				data:     nil,
				dataHash: "da39a3ee",
			},
			false,
		},
		{
			"data",
			"data",
			map[string]interface{}{
				"foo": "bar",
			},
			&VaultWriteQuery{
				path: "data",
				data: map[string]interface{}{
					"foo": "bar",
				},
				dataHash: "ab03a894",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewVaultWriteQuery(tc.i, tc.d)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
				act.sleepCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestVaultWriteSecretKV_Fetch(t *testing.T) {
	// previously triggered a nil-pointer-deref panic in wq.Fetch() with KVv1
	// due to writeSecret() returning nil for vaultSecret
	// see GH-1252
	t.Run("write_secret_v1", func(t *testing.T) {
		clients, vault := testVaultServer(t, "write_secret_v1", "1")
		secretsPath := vault.secretsPath

		path := secretsPath + "/foo"
		exp := map[string]interface{}{
			"bar": "zed",
		}

		wq, err := NewVaultWriteQuery(path, exp)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = wq.Fetch(clients, &QueryOptions{})
		if err != nil {
			fmt.Println(err)
		}

		rq, err := NewVaultReadQuery(path)
		if err != nil {
			t.Fatal(err)
		}
		act, err := rq.readSecret(clients)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, exp, act.Data)
	})

	// previously triggered vault returning "no data provided" with KVv2 as the
	// data structure passed in didn't have additional wrapping map with the
	// "data" key as used in KVv2
	// see GH-1252
	t.Run("write_secret_v2", func(t *testing.T) {
		clients, vault := testVaultServer(t, "write_secret_v2", "2")
		secretsPath := vault.secretsPath

		path := secretsPath + "/data/foo"
		exp := map[string]interface{}{
			"bar": "zed",
		}

		wq, err := NewVaultWriteQuery(path, exp)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = wq.Fetch(clients, &QueryOptions{})
		if err != nil {
			fmt.Println(err)
		}

		rq, err := NewVaultReadQuery(path)
		if err != nil {
			t.Fatal(err)
		}
		act, err := rq.readSecret(clients)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, exp, act.Data["data"])
	})

	// VaultWriteQuery should work properly on kv-v2 secrets engines if /data/
	// is not present on secret path
	t.Run("write_secret_v2_without_data_in_path", func(t *testing.T) {
		clients, vault := testVaultServer(t, "write_secret_v2_without_data_in_path", "2")
		secretsPath := vault.secretsPath

		path := secretsPath + "/foo"
		exp := map[string]interface{}{
			"bar": "zed",
		}

		wq, err := NewVaultWriteQuery(path, exp)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = wq.Fetch(clients, &QueryOptions{})
		if err != nil {
			fmt.Println(err)
		}

		rq, err := NewVaultReadQuery(path)
		if err != nil {
			t.Fatal(err)
		}
		act, err := rq.readSecret(clients)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, exp, act.Data["data"])
	})
}

func TestVaultWriteQuery_Fetch(t *testing.T) {
	clients := testClients

	if err := clients.Vault().Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := clients.Vault().Logical().Write("transit/keys/test", nil); err != nil {
		t.Fatal(err)
	}

	b64 := func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}

	cases := []struct {
		name string
		i    string
		d    map[string]interface{}
		exp  interface{}
		err  bool
	}{
		{
			"encrypt",
			"transit/encrypt/test",
			map[string]interface{}{
				"plaintext": b64("test"),
			},
			&Secret{
				Data: map[string]interface{}{
					"ciphertext":  "",
					"key_version": "",
				},
			},
			false,
		},
		{
			"no_exist",
			"not/a/real/path/like/ever",
			nil,
			nil,
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultWriteQuery(tc.i, tc.d)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(clients, nil)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.(*Secret).RequestID = ""
				act.(*Secret).LeaseID = ""
				act.(*Secret).LeaseDuration = 0
				act.(*Secret).Renewable = false
				if act.(*Secret).Data["ciphertext"] != "" {
					act.(*Secret).Data["ciphertext"] = ""
					act.(*Secret).Data["key_version"] = ""
				}
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewVaultWriteQuery("transit/encrypt/test", map[string]interface{}{
			"plaintext": b64("test"),
		})
		if err != nil {
			t.Fatal(err)
		}

		dataCh := make(chan interface{}, 1)
		errCh := make(chan error, 1)
		go func() {
			for {
				data, _, err := d.Fetch(clients, nil)
				if err != nil {
					errCh <- err
					return
				}
				select {
				case dataCh <- data:
				case <-d.stopCh:
				}
			}
		}()

		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-dataCh:
		}

		d.Stop()

		select {
		case err := <-errCh:
			if err != ErrStopped {
				t.Fatal(err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	t.Run("fires_changes", func(t *testing.T) {
		d, err := NewVaultWriteQuery("transit/encrypt/test", map[string]interface{}{
			"plaintext": b64("test"),
		})
		if err != nil {
			t.Fatal(err)
		}

		_, qm, err := d.Fetch(clients, nil)
		if err != nil {
			t.Fatal(err)
		}

		dataCh := make(chan interface{}, 1)
		errCh := make(chan error, 1)
		go func() {
			data, _, err := d.Fetch(clients, &QueryOptions{WaitIndex: qm.LastIndex})
			if err != nil {
				errCh <- err
				return
			}
			dataCh <- data
		}()

		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-dataCh:
		}
	})

	t.Run("nonrenewable-sleeper", func(t *testing.T) {
		d, err := NewVaultWriteQuery("transit/encrypt/test",
			map[string]interface{}{
				"plaintext": b64("test"),
			})
		if err != nil {
			t.Fatal(err)
		}

		_, qm, err := d.Fetch(clients, nil)
		if err != nil {
			t.Fatal(err)
		}

		errCh := make(chan error, 1)
		go func() {
			_, _, err := d.Fetch(clients,
				&QueryOptions{WaitIndex: qm.LastIndex})
			if err != nil {
				errCh <- err
			}
			close(errCh)
		}()

		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if len(d.sleepCh) != 1 {
			t.Fatalf("sleep channel has len %v, expected 1", len(d.sleepCh))
		}
		dur := <-d.sleepCh
		if dur > 0 {
			t.Fatalf("duration of sleep should be > 0")
		}
	})
}

func TestVaultWriteQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		d    map[string]interface{}
		exp  string
	}{
		{
			"path_nil_data",
			"path",
			nil,
			"vault.write(path -> da39a3ee)",
		},
		{
			"path_data",
			"path",
			map[string]interface{}{
				"foo": "bar",
			},
			"vault.write(path -> ab03a894)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultWriteQuery(tc.i, tc.d)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
