// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault/seal"
)

// SealAccess is a wrapper around Seal that exposes accessor methods
// through Core.SealAccess() while restricting the ability to modify
// Core.seal itself.
type SealAccess struct {
	seal Seal
}

func NewSealAccess(seal Seal) *SealAccess {
	return &SealAccess{seal: seal}
}

func (s *SealAccess) StoredKeysSupported() seal.StoredKeysSupport {
	return s.seal.StoredKeysSupported()
}

func (s *SealAccess) BarrierType() wrapping.WrapperType {
	return s.seal.BarrierType()
}

func (s *SealAccess) BarrierConfig(ctx context.Context) (*SealConfig, error) {
	return s.seal.BarrierConfig(ctx, namespace.RootNamespace)
}

func (s *SealAccess) RecoveryKeySupported() bool {
	return s.seal.RecoveryKeySupported()
}

func (s *SealAccess) RecoveryType() string {
	return s.seal.RecoveryType()
}

func (s *SealAccess) RecoveryConfig(ctx context.Context) (*SealConfig, error) {
	return s.seal.RecoveryConfig(ctx)
}

func (s *SealAccess) VerifyRecoveryKey(ctx context.Context, key []byte) error {
	return s.seal.VerifyRecoveryKey(ctx, key)
}

// TODO(SEALHA): This looks like it belongs in Seal instead, it only has two callers
func (s *SealAccess) ClearCaches(ctx context.Context) {
	s.seal.SetBarrierConfig(ctx, nil, namespace.RootNamespace)
	if s.RecoveryKeySupported() {
		s.seal.SetRecoveryConfig(ctx, nil)
	}
}

func (s *SealAccess) GetAccess() seal.Access {
	return s.seal.GetAccess()
}
