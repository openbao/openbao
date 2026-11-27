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
		newSeal.SetCachedConfig(&SealConfig{
			SecretThreshold: 1,
			SecretShares:    1,
		})
		return newSeal
	default:
		access, _ := seal.NewTestSeal(opts)
		seal, err := NewAutoSeal(access)
		if err != nil {
			t.Fatal(err)
		}
		return seal
	}
}

func TestCoreUnsealedWithConfigs(t testing.T, conf *SealConfig) (*Core, [][]byte, string) {
	t.Helper()
	return TestCoreUnsealedWithConfigSealOpts(t, conf, &seal.TestSealOpts{Wrapper: seal.WrapperTypeShamir})
}

func TestCoreUnsealedWithConfigSealOpts(t testing.T, conf *SealConfig, sealOpts *seal.TestSealOpts) (*Core, [][]byte, string) {
	t.Helper()
	seal := NewTestSeal(t, sealOpts)
	core := TestCoreWithSeal(t, seal, false)
	ctx := namespace.RootContext(context.Background())
	result, err := core.Initialize(ctx, &InitParams{
		SealConfig: conf,
	})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if err = core.UnsealWithStoredKeys(ctx); err != nil && IsFatalError(err) {
		t.Fatalf("err: %s", err)
	}

	if core.Sealed() {
		for _, key := range result.SecretShares {
			if _, err := core.Unseal(TestKeyCopy(key)); err != nil {
				t.Fatalf("unseal err: %s", err)
			}
		}

		if core.Sealed() {
			t.Fatal("should not be sealed")
		}
	}

	if seal.RecoveryKeySupported() {
		return core, result.RecoveryShares, result.RootToken
	}

	return core, result.SecretShares, result.RootToken
}
