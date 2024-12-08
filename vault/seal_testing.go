// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	testing "github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/vault/seal"
)

func TestCoreUnsealedWithConfigs(t testing.T, barrierConf, recoveryConf *SealConfig) (*Core, [][]byte, [][]byte, string) {
	t.Helper()
	opts := &seal.TestSealOpts{}
	if recoveryConf == nil {
		opts.StoredKeys = seal.StoredKeysSupportedShamirRoot
	}
	return TestCoreUnsealedWithConfigSealOpts(t, barrierConf, recoveryConf, opts)
}

func TestCoreUnsealedWithConfigSealOpts(t testing.T, barrierConf, recoveryConf *SealConfig, sealOpts *seal.TestSealOpts) (*Core, [][]byte, [][]byte, string) {
	t.Helper()
	seal := NewTestSeal(t, sealOpts)
	core := TestCoreWithSeal(t, seal, false)
	result, err := core.Initialize(context.Background(), &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	err = core.UnsealWithStoredKeys(context.Background())
	if err != nil && IsFatalError(err) {
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

	return core, result.SecretShares, result.RecoveryShares, result.RootToken
}
