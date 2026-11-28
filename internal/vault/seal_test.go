// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDefaultSeal_Config exercises Shamir SetBarrierConfig and BarrierConfig.
// Note that this is a little questionable, because we're doing an init and
// unseal, then changing the barrier config using an internal function instead
// of an API.  In other words if your change break this test, it might be more
// the test's fault than your changes.
func TestDefaultSeal_Config(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    4,
		SecretThreshold: 2,
	}
	core, _, _ := TestCoreUnsealed(t)

	defSeal := NewDefaultSeal(nil)
	defSeal.SetCore(core)
	err := defSeal.SetBarrierConfig(t.Context(), bc)
	require.NoError(t, err)

	newBc, err := defSeal.BarrierConfig(t.Context())
	require.NoError(t, err)
	if !reflect.DeepEqual(*bc, *newBc) {
		t.Fatal("config mismatch")
	}

	// Now, test without the benefit of the cached value in the seal
	defSeal = NewDefaultSeal(nil)
	defSeal.SetCore(core)
	newBc, err = defSeal.BarrierConfig(t.Context())
	require.NoError(t, err)
	if !reflect.DeepEqual(*bc, *newBc) {
		t.Fatal("config mismatch")
	}
}

func TestSealConfig_Validate_KMS(t *testing.T) {
	cases := []struct {
		name    string
		config  *SealConfig
		wantErr bool
	}{
		{
			name:    "shamir with valid shares and threshold",
			config:  &SealConfig{Type: "shamir", SecretShares: 3, SecretThreshold: 2},
			wantErr: false,
		},
		{
			name:    "empty type treated as shamir, valid",
			config:  &SealConfig{SecretShares: 1, SecretThreshold: 1},
			wantErr: false,
		},
		{
			name:    "shamir with zero shares fails validation",
			config:  &SealConfig{Type: "shamir", SecretShares: 0},
			wantErr: true,
		},
		{
			name:    "transit skips share and threshold checks",
			config:  &SealConfig{Type: "transit", KMSConfig: map[string]string{"key_name": "my-key"}},
			wantErr: false,
		},
		{
			name:    "awskms skips share and threshold checks",
			config:  &SealConfig{Type: "awskms"},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSealConfig_Clone_KMSConfig(t *testing.T) {
	orig := &SealConfig{
		Type: "transit",
		KMSConfig: map[string]string{
			"key_name": "test-key",
			"address":  "http://vault:8200",
		},
	}
	clone := orig.Clone()
	require.Equal(t, orig.KMSConfig, clone.KMSConfig)

	// Mutating the clone must not affect the original.
	clone.KMSConfig["key_name"] = "mutated"
	require.Equal(t, "test-key", orig.KMSConfig["key_name"])
}
