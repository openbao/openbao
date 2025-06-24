// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/go-hclog"
	testing "github.com/mitchellh/go-testing-interface"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/vault/seal"
)

func NewTestSeal(t testing.T, opts *seal.TestSealOpts) Seal {
	t.Helper()
	if opts == nil {
		opts = &seal.TestSealOpts{}
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewVaultLogger(hclog.Debug)
	}

	switch opts.StoredKeys {
	case seal.StoredKeysSupportedShamirRoot:
		newSeal := NewDefaultSeal(seal.NewAccess(aeadwrapper.NewShamirWrapper()))
		// Need StoredShares set or this will look like a legacy shamir seal.
		newSeal.SetCachedConfig(&SealConfig{
			StoredShares:    1,
			SecretThreshold: 1,
			SecretShares:    1,
		})
		return newSeal
	case seal.StoredKeysNotSupported:
		t.Fatal("Legacy shamir's seal no longer supported")
		return nil
	default:
		access, _ := seal.NewTestSeal(opts)
		seal, err := NewAutoSeal(access)
		if err != nil {
			t.Fatal(err)
		}
		return seal
	}
}
