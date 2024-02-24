// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestNewVaultTokenQuery(t *testing.T) {
	cases := []struct {
		name string
		exp  *VaultTokenQuery
		err  bool
	}{
		{
			"default",
			&VaultTokenQuery{
				secret: &Secret{
					Auth: &SecretAuth{
						ClientToken:   "my-token",
						Renewable:     true,
						LeaseDuration: 1,
					},
				},
				vaultSecret: &api.Secret{
					Auth: &api.SecretAuth{
						ClientToken:   "my-token",
						Renewable:     true,
						LeaseDuration: 1,
					},
				},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewVaultTokenQuery("my-token")
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

func TestVaultTokenQuery_String(t *testing.T) {
	cases := []struct {
		name string
		exp  string
	}{
		{
			"default",
			"vault.token",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewVaultTokenQuery("my-token")
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
