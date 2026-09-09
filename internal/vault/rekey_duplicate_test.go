// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCore_Rekey_DuplicateShares(t *testing.T) {
	for _, tc := range []struct {
		name         string
		recovery     bool
		verification bool
	}{
		{name: "barrier"},
		{name: "recovery", recovery: true},
		{name: "barrier-with-verification", verification: true},
		{name: "recovery-with-verification", recovery: true, verification: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			barrierConf := &SealConfig{SecretShares: 4, SecretThreshold: 4}
			var recoveryConf *SealConfig
			if tc.recovery {
				recoveryConf = &SealConfig{SecretShares: 4, SecretThreshold: 4}
				barrierConf = &SealConfig{SecretShares: 1, SecretThreshold: 1}
			}
			c, keys, recoveryKeys, _ := TestCoreUnsealedWithConfigs(t, barrierConf, recoveryConf)
			sealType := c.seal.BarrierType().String()
			duplicateError := "given key has already been provided during this generation operation"
			if tc.recovery {
				keys = recoveryKeys
				sealType = c.seal.RecoveryType()
				duplicateError = "given key has already been provided during this rekey operation"
			}
			require.Len(t, keys, 4)
			require.NoError(t, c.RekeyInit(&SealConfig{
				Type:                 sealType,
				SecretShares:         4,
				SecretThreshold:      4,
				VerificationRequired: tc.verification,
			}, tc.recovery))
			conf, err := c.RekeyConfig(tc.recovery)
			require.NoError(t, err)
			require.NotNil(t, conf)
			nonce := conf.Nonce
			require.NotEmpty(t, nonce)

			assertProgress := func(verification bool, want int, verificationNonce string) {
				t.Helper()
				started, progress, err := c.RekeyProgress(tc.recovery, verification)
				require.NoError(t, err)
				require.True(t, started)
				require.Equal(t, want, progress)
				conf, err := c.RekeyConfig(tc.recovery)
				require.NoError(t, err)
				require.NotNil(t, conf)
				require.Equal(t, nonce, conf.Nonce)
				require.Equal(t, verificationNonce, conf.VerificationNonce)
			}
			assertProgress(false, 0, "")

			for i, key := range keys[:3] {
				result, err := c.RekeyUpdate(t.Context(), TestKeyCopy(key), nonce, tc.recovery)
				require.NoError(t, err)
				require.Nil(t, result)
				assertProgress(false, i+1, "")
			}
			// Retry the first, middle, and last stored share before completing the threshold.
			for i, key := range keys[:3] {
				result, err := c.RekeyUpdate(t.Context(), TestKeyCopy(key), nonce, tc.recovery)
				require.EqualError(t, err, duplicateError, "duplicate at position %d", i)
				require.Equal(t, http.StatusBadRequest, err.Code())
				require.Nil(t, result)
				assertProgress(false, 3, "")
			}
			result, err := c.RekeyUpdate(t.Context(), TestKeyCopy(keys[3]), nonce, tc.recovery)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Len(t, result.SecretShares, 4)
			require.Equal(t, tc.verification, result.VerificationRequired)

			if tc.verification {
				verificationNonce := result.VerificationNonce
				require.NotEmpty(t, verificationNonce)
				assertProgress(false, 0, verificationNonce)
				assertProgress(true, 0, verificationNonce)
				for i, key := range result.SecretShares[:3] {
					verified, err := c.RekeyVerify(t.Context(), TestKeyCopy(key), verificationNonce, tc.recovery)
					require.NoError(t, err)
					require.Nil(t, verified)
					assertProgress(true, i+1, verificationNonce)
				}
				for i, key := range result.SecretShares[:3] {
					verified, err := c.RekeyVerify(t.Context(), TestKeyCopy(key), verificationNonce, tc.recovery)
					require.EqualError(t, err, "given key has already been provided during this verify operation", "duplicate at position %d", i)
					require.Equal(t, http.StatusBadRequest, err.Code())
					require.Nil(t, verified)
					assertProgress(true, 3, verificationNonce)
				}
				verified, err := c.RekeyVerify(t.Context(), TestKeyCopy(result.SecretShares[3]), verificationNonce, tc.recovery)
				require.NoError(t, err)
				require.NotNil(t, verified)
				require.True(t, verified.Complete)
				require.Equal(t, verificationNonce, verified.Nonce)
			}

			conf, err = c.RekeyConfig(tc.recovery)
			require.NoError(t, err)
			require.Nil(t, conf)
			_, _, err = c.RekeyProgress(tc.recovery, false)
			require.EqualError(t, err, "rekey operation not in progress")
			require.Equal(t, http.StatusBadRequest, err.Code())
		})
	}
}
