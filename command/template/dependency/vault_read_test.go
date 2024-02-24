// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVaultReadQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *VaultReadQuery
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
			&VaultReadQuery{
				rawPath:     "path",
				queryValues: url.Values{},
			},
			false,
		},
		{
			"leading_slash",
			"/leading/slash",
			&VaultReadQuery{
				rawPath:     "leading/slash",
				queryValues: url.Values{},
			},
			false,
		},
		{
			"trailing_slash",
			"trailing/slash/",
			&VaultReadQuery{
				rawPath:     "trailing/slash",
				queryValues: url.Values{},
			},
			false,
		},
		{
			"query_param",
			"path?version=3",
			&VaultReadQuery{
				rawPath: "path",
				queryValues: url.Values{
					"version": []string{"3"},
				},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewVaultReadQuery(tc.i)
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

func TestVaultReadQuery_Fetch_KVv1(t *testing.T) {
	clients, vault := testVaultServer(t, "read_fetch_v1", "1")
	secretsPath := vault.secretsPath
	// Enable v1 kv for versioned secrets
	vc := clients.Vault()
	if err := vc.Sys().TuneMount(secretsPath, api.MountConfigInput{
		Options: map[string]string{
			"version": "1",
		},
	}); err != nil {
		t.Fatalf("Error tuning secrets engine: %s", err)
	}

	err := vault.CreateSecret("foo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zap",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		i    string
		exp  interface{}
		err  bool
	}{
		{
			"exists",
			secretsPath + "/foo/bar",
			&Secret{
				Data: map[string]interface{}{
					"ttl": "100ms",
					"zip": "zap",
				},
			},
			false,
		},
		{
			"no_exist",
			"not/a/real/path/like/ever",
			nil,
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultReadQuery(tc.i)
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
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewVaultReadQuery(secretsPath + "/foo/bar")
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
		case <-time.After(500 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	t.Run("fires_changes", func(t *testing.T) {
		d, err := NewVaultReadQuery(secretsPath + "/foo/bar")
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
		d, err := NewVaultReadQuery(secretsPath + "/foo/bar")
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

func TestVaultReadQuery_Fetch_KVv2(t *testing.T) {
	clients, vault := testVaultServer(t, "read_fetch_v2", "2")
	secretsPath := vault.secretsPath

	// Write an initial value to the secret path
	err := vault.CreateSecret("data/foo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zap",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write a new value to increment the version
	err = vault.CreateSecret("data/foo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zop",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write a different secret with the path containing "data/data*/" prefix
	err = vault.CreateSecret("data/datafoo/bar", map[string]interface{}{
		"ttl": "100ms", // explicitly make this a short duration for testing
		"zip": "zop",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		i    string
		exp  interface{}
		err  bool
	}{
		{
			"exists",
			secretsPath + "/foo/bar",
			&Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"ttl": "100ms", // explicitly make this a short duration for testing
						"zip": "zop",
					},
				},
			},
			false,
		},
		{
			"/data in path",
			secretsPath + "/data/foo/bar",
			&Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"ttl": "100ms", // explicitly make this a short duration for testing
						"zip": "zop",
					},
				},
			},
			false,
		},
		{
			"version=1",
			secretsPath + "/foo/bar?version=1",
			&Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"ttl": "100ms", // explicitly make this a short duration for testing
						"zip": "zap",
					},
				},
			},
			false,
		},
		{
			"/data in path and in prefix",
			secretsPath + "/data/datafoo/bar",
			&Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"ttl": "100ms",
						"zip": "zop",
					},
				},
			},
			false,
		},
		{
			"without /data/ in path, but contains data prefix",
			secretsPath + "/datafoo/bar",
			&Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"ttl": "100ms",
						"zip": "zop",
					},
				},
			},
			false,
		},
		{
			"no_exist",
			"not/a/real/path/like/ever",
			nil,
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultReadQuery(tc.i)
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
				tc.exp.(*Secret).Data["metadata"] = act.(*Secret).Data["metadata"]
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("read_metadata", func(t *testing.T) {
		d, err := NewVaultReadQuery(secretsPath + "/metadata/foo/bar")
		require.NoError(t, err)

		act, _, err := d.Fetch(clients, nil)
		require.NoError(t, err)
		require.NotNil(t, act)

		versions := act.(*Secret).Data["versions"]
		assert.Len(t, versions, 2)
	})

	t.Run("read_deleted", func(t *testing.T) {
		// only needed for KVv2 as KVv1 doesn't have metadata
		path := "data/foo/zed"
		// create and delete a secret
		err = vault.CreateSecret(path, map[string]interface{}{
			"zip": "zop",
		})
		if err != nil {
			t.Fatal(err)
		}
		err = vault.deleteSecret(path)
		if err != nil {
			t.Fatal(err)
		}
		// now look for entry with metadata but no data (deleted secret)
		path = vault.secretsPath + "/" + path
		d, err := NewVaultReadQuery(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = d.Fetch(clients, nil)
		if err == nil {
			t.Fatal("Nil received when error expected")
		}
		exp_err := fmt.Sprintf("no secret exists at %s", path)
		if errors.Cause(err).Error() != exp_err {
			t.Fatalf("Unexpected error received.\nexpected '%s'\ngot: '%s'",
				exp_err, errors.Cause(err))
		}
	})

	t.Run("stops", func(t *testing.T) {
		d, err := NewVaultReadQuery(secretsPath + "/foo/bar")
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
		case <-time.After(500 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	for _, dataPrefix := range []string{"", "/data"} {
		t.Run(fmt.Sprintf("fires_changes%s", dataPrefix), func(t *testing.T) {
			d, err := NewVaultReadQuery(fmt.Sprintf("%s%s/foo/bar",
				secretsPath, dataPrefix))
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
}

// TestVaultReadQuery_Fetch_PKI_Anonymous asserts that vault.read can fetch a
// pki ca public cert even even when running unauthenticated client.
func TestVaultReadQuery_Fetch_PKI_Anonymous(t *testing.T) {
	clients := testClients

	vc := clients.Vault()
	_, err := vc.Logical().Write("sys/policies/acl/secrets-only",
		map[string]interface{}{
			"policy": `path "secret/*" { capabilities = ["create", "read"] }`,
		})
	if err != nil {
		t.Fatal(err)
	}

	anonClient := NewClientSet()
	anonClient.CreateVaultClient(&CreateVaultClientInput{
		Address: vaultAddr,
		Token:   "",
	})
	_, err = anonClient.vault.client.Auth().Token().LookupSelf()
	// 'missing client token' vault <1.9.7, 'permission denied' vault >1.10.0
	if err == nil ||
		!(strings.Contains(err.Error(), "missing client token") ||
			strings.Contains(err.Error(), "permission denied")) {
		// check environment for VAULT_TOKEN
		t.Fatalf("expected a 'missing client token' (vault < 1.10) or 'permission denied' error but found: %v", err)
	}

	d, err := NewVaultReadQuery("pki/cert/ca")
	if err != nil {
		t.Fatal(err)
	}

	act, _, err := d.Fetch(anonClient, nil)
	if err != nil {
		t.Fatal(err)
	}

	sec, ok := act.(*Secret)
	if !ok {
		t.Fatalf("expected secret but found %v", reflect.TypeOf(act))
	}

	cert, ok := sec.Data["certificate"].(string)
	if !ok || !strings.Contains(cert, "BEGIN") {
		t.Fatalf("expected a cert but found: %v", cert)
	}
}

// TestVaultReadQuery_Fetch_NonSecrets asserts that vault.read can fetch a
// non-secret
func TestVaultReadQuery_Fetch_NonSecrets(t *testing.T) {
	var err error

	clients := testClients

	vc := clients.Vault()

	err = vc.Sys().EnableAuth("approle", "approle", "")
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		t.Fatalf("(%T) %s\n", err, err)
	}

	_, err = vc.Logical().Write("auth/approle/role/my-approle", nil)
	if err != nil {
		t.Fatal(err)
	}

	// create restricted token
	_, err = vc.Logical().Write("sys/policies/acl/operator",
		map[string]interface{}{
			"policy": `path "auth/approle/role/my-approle/role-id" { capabilities = ["read"] }`,
		})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := vc.Auth().Token().Create(&api.TokenCreateRequest{
		Policies: []string{"operator"},
	})
	if err != nil {
		t.Fatal(err)
	}

	anonClient := NewClientSet()
	anonClient.CreateVaultClient(&CreateVaultClientInput{
		Address: vaultAddr,
		Token:   secret.Auth.ClientToken,
	})
	_, err = anonClient.vault.client.Auth().Token().LookupSelf()
	if err != nil {
		t.Fatal(err)
	}

	d, err := NewVaultReadQuery("auth/approle/role/my-approle/role-id")
	if err != nil {
		t.Fatal(err)
	}

	act, _, err := d.Fetch(anonClient, nil)
	if err != nil {
		t.Fatal(err)
	}

	sec, ok := act.(*Secret)
	if !ok {
		t.Fatalf("expected secret but found %v", reflect.TypeOf(act))
	}
	if _, ok := sec.Data["role_id"]; !ok {
		t.Fatalf("expected to find role_id but found: %v", sec.Data)
	}
}

func TestVaultReadQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"path",
			"path",
			"vault.read(path)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultReadQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}

func TestShimKVv2Path(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		mountPath string
		expected  string
	}{
		{
			"full path",
			"secret/data/foo/bar",
			"secret/",
			"secret/data/foo/bar",
		}, {
			"data prefix added",
			"secret/foo/bar",
			"secret/",
			"secret/data/foo/bar",
		}, {
			"full path with data* in subpath",
			"secret/data/datafoo/bar",
			"secret/",
			"secret/data/datafoo/bar",
		}, {
			"prefix added with data* in subpath",
			"secret/datafoo/bar",
			"secret/",
			"secret/data/datafoo/bar",
		}, {
			"prefix added with *data in subpath",
			"secret/foodata/foo/bar",
			"secret/",
			"secret/data/foodata/foo/bar",
		}, {
			"prefix not added to metadata",
			"secret/metadata/foo/bar",
			"secret/",
			"secret/metadata/foo/bar",
		}, {
			"prefix added with metadata* in subpath",
			"secret/metadatafoo/foo/bar",
			"secret/",
			"secret/data/metadatafoo/foo/bar",
		}, {
			"prefix added with *metadata in subpath",
			"secret/foometadata/foo/bar",
			"secret/",
			"secret/data/foometadata/foo/bar",
		}, {
			"prefix added to mount path",
			"secret/",
			"secret/",
			"secret/data",
		}, {
			"prefix added to mount path not exact match",
			"secret",
			"secret/",
			"secret/data",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual := shimKVv2Path(tc.path, tc.mountPath)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
