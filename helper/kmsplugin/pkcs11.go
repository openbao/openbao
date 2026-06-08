// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package kmsplugin

import (
	"github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2"
)

func init() {
	// We do not mark the PKCS#11 wrapper as deprecated as a more specific
	// warning is printed at server startup when the HSM distribution is used.
	builtinWrappers[pkcs11.Type] = builtinWrapper{toWrapper(pkcs11.NewWrapper), false}
}
