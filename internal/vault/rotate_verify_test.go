// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestVerifyRotation_DistinctShares(t *testing.T) {
	for _, name := range []string{"root", "child"} {
		t.Run(name, func(t *testing.T) {
			c, keys, _, _ := TestCoreUnsealedWithConfigs(t, &SealConfig{
				SecretShares:    1,
				SecretThreshold: 1,
			}, nil)
			ns := namespace.RootNamespace
			if name == "child" {
				ns = &namespace.Namespace{Path: "ns1/"}
				keys = TestCoreCreateUnsealedNamespaces(t, c, ns)[ns.Path]
			}
			ctx := namespace.ContextWithNamespace(t.Context(), ns)
			sm := c.sealManager
			seal := sm.NamespaceSeal(ns.UUID)
			require.NotNil(t, seal)
			result, err := sm.InitRotation(ctx, ns, &SealConfig{
				Type:                 seal.BarrierType().String(),
				SecretShares:         3,
				SecretThreshold:      3,
				VerificationRequired: true,
			}, false)
			require.NoError(t, err)
			require.Nil(t, result)
			conf := sm.RotationConfig(ns.UUID, false)
			require.NotNil(t, conf)
			nonce := conf.Nonce
			require.NotEmpty(t, nonce)
			for _, key := range keys {
				result, err = sm.UpdateRotation(ctx, ns, TestKeyCopy(key), nonce, false)
				require.NoError(t, err)
				if result != nil {
					break
				}
			}
			require.NotNil(t, result)
			require.Len(t, result.SecretShares, 3)
			require.True(t, result.VerificationRequired)
			verificationNonce := result.VerificationNonce
			require.NotEmpty(t, verificationNonce)

			for i, key := range result.SecretShares[:2] {
				verified, err := sm.VerifyRotation(ctx, ns, TestKeyCopy(key), verificationNonce, false)
				require.NoError(t, err)
				require.Nil(t, verified)
				conf = sm.RotationConfig(ns.UUID, false)
				require.NotNil(t, conf)
				require.Len(t, conf.VerificationProgress, i+1)
				require.Equal(t, nonce, conf.Nonce)
				require.Equal(t, verificationNonce, conf.VerificationNonce)
			}
			verified, err := sm.VerifyRotation(ctx, ns, TestKeyCopy(result.SecretShares[2]), verificationNonce, false)
			require.NoError(t, err)
			require.Equal(t, &RekeyVerifyResult{Complete: true, Nonce: verificationNonce}, verified)
			require.Nil(t, sm.RotationConfig(ns.UUID, false))

			sealConf, err := seal.BarrierConfig(ctx)
			require.NoError(t, err)
			require.NotNil(t, sealConf)
			require.Equal(t, 3, sealConf.SecretShares)
			require.Equal(t, 3, sealConf.SecretThreshold)
		})
	}
}
