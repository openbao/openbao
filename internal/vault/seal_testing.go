// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/go-hclog"
	testing "github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

func NewTestSeal(t testing.T, opts *seal.TestSealOpts) Seal {
	t.Helper()
	if opts == nil {
		opts = &seal.TestSealOpts{}
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewVaultLogger(hclog.Debug)
	}

	switch opts.Wrapper {
	case seal.WrapperTypeShamir:
		newSeal := NewDefaultSeal(seal.NewAccess(seal.NewShamirWrapper()))
		newSeal.SetCachedBarrierConfig(&SealConfig{
			SecretThreshold: 1,
			SecretShares:    1,
		})
		return newSeal
	default:
		access, _ := seal.NewTestSeal(opts)
		seal, err := NewAutoSeal(access)
		require.NoError(t, err)
		return seal
	}
}

func TestCoreUnsealedWithConfigs(t testing.T, barrierConf, recoveryConf *SealConfig) (*Core, [][]byte, [][]byte, string) {
	t.Helper()
	opts := &seal.TestSealOpts{}
	if recoveryConf == nil {
		opts.Wrapper = seal.WrapperTypeShamir
	}
	return TestCoreUnsealedWithConfigSealOpts(t, barrierConf, recoveryConf, opts)
}

func TestCoreUnsealedWithConfigSealOpts(t testing.T, barrierConf, recoveryConf *SealConfig, sealOpts *seal.TestSealOpts) (*Core, [][]byte, [][]byte, string) {
	t.Helper()
	seal := NewTestSeal(t, sealOpts)
	core := TestCoreWithSeal(t, seal, false)
	ctx := namespace.RootContext(context.Background())
	result, err := core.Initialize(ctx, &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.NoError(t, err)
	if err = core.UnsealWithStoredKeys(ctx); err != nil && IsFatalError(err) {
		t.Fatalf("err: %s", err)
	}

	if core.Sealed() {
		for _, key := range result.SecretShares {
			_, err = core.Unseal(TestKeyCopy(key))
			require.NoError(t, err, "unseal err")
		}

		if core.Sealed() {
			t.Fatal("should not be sealed")
		}
	}

	return core, result.SecretShares, result.RecoveryShares, result.RootToken
}
