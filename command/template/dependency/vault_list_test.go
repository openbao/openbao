// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewVaultListQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *VaultListQuery
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"path",
			"path",
			&VaultListQuery{
				path: "path",
			},
			false,
		},
		{
			"leading_slash",
			"/leading/slash",
			&VaultListQuery{
				path: "leading/slash",
			},
			false,
		},
		{
			"trailing_slash",
			"trailing/slash/",
			&VaultListQuery{
				path: "trailing/slash",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewVaultListQuery(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestVaultListQuery_Fetch(t *testing.T) {
	clients, vault := testVaultServer(t, "listfetch", "1")
	secretsPath := vault.secretsPath

	clientsKvV2, vaultKvV2 := testVaultServer(t, "listfetchV2", "2")
	secretsPathV2 := vaultKvV2.secretsPath

	err := vault.CreateSecret("foo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zap",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = vaultKvV2.CreateSecret("foo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zap",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		i       string
		exp     []string
		clients *ClientSet
	}{
		{
			"exists",
			secretsPath,
			[]string{"foo/"},
			clients,
		},
		{
			"no_exist",
			"not/a/real/path/like/ever",
			nil,
			clients,
		},
		{
			"exists kv-v2",
			secretsPathV2,
			[]string{"foo/"},
			clientsKvV2,
		},
		{
			"no_exist kv-v2",
			"not/a/real/path/like/ever",
			nil,
			clientsKvV2,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultListQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(tc.clients, nil)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewVaultListQuery(secretsPath + "/foo/bar")
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
				dataCh <- data
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
		d, err := NewVaultListQuery(secretsPath)
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
}

func TestVaultListQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"path",
			"path",
			"vault.list(path)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultListQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
