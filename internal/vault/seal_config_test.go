// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealConfig_Validate(t *testing.T) {
	t.Parallel()
	tc := map[string]struct {
		config    *SealConfig
		wantError error
	}{
		"primary_not_enough_shares": {
			config: &SealConfig{
				Purpose:         Primary,
				SecretShares:    0,
				SecretThreshold: 0,
			},
			wantError: errors.New("shares must be at least one"),
		},
		"primary_not_enough_threshold": {
			config: &SealConfig{
				Purpose:         Primary,
				SecretShares:    1,
				SecretThreshold: 0,
			},
			wantError: errors.New("threshold must be at least one"),
		},
		"primary_happy_path": {
			config: &SealConfig{
				Purpose:         Primary,
				SecretShares:    5,
				SecretThreshold: 3,
			},
		},
		"recovery_deferred_init": {
			config: &SealConfig{
				Purpose:         Recovery,
				SecretShares:    0,
				SecretThreshold: 0,
			},
		},
		"recovery_happy_path": {
			config: &SealConfig{
				Purpose:         Recovery,
				SecretShares:    5,
				SecretThreshold: 3,
			},
		},
	}

	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantError != nil {
				require.ErrorContains(t, err, tt.wantError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
