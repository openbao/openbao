// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package kmsplugin

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2"
)

func init() {
	builtinWrappers[wrapping.WrapperTypePkcs11] = toWrapper(pkcs11.NewWrapper)
}
