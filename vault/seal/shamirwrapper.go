// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package seal

import (
	"context"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/aead"
)

// TODO(satoqz): Remove ShamirWrapper from go-kms-wrapping & replace remaining
// references to wrapping.WrapperTypeShamir with vaultseal.WrapperTypeShamir.
const WrapperTypeShamir wrapping.WrapperType = "shamir"

// ShamirWrapper is here for backwards compatibility for Vault; it reports a
// type of "shamir" instead of "aead".
type ShamirWrapper struct {
	*aead.Wrapper
}

// NewShamirWrapper returns a type of "shamir" instead of "aead" and is for backwards
// compatibility with old versions of Vault.
func NewShamirWrapper() *ShamirWrapper {
	return &ShamirWrapper{
		Wrapper: aead.NewWrapper(),
	}
}

func (s *ShamirWrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeShamir, nil
}
