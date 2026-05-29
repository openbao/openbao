// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm

package server

import (
	"github.com/hashicorp/go-hclog"
)

func WarnHSMDeprecated(logger hclog.Logger) {
	logger.Warn(
		"The HSM distribution of OpenBao is discontinued and will no " +
			"longer receive updates beyond this minor version. PKCS#11 support has " +
			"not been removed, but is now available via an external KMS plugin that " +
			"is drop-in compatible with the previously built-in PKCS#11 seal. " +
			"To remove this warning, migrate your deployment to the default distribution " +
			"of OpenBao and use the PKCS#11 KMS plugin to regain PKCS#11 seal functionality. " +
			"For more information, see https://openbao.org/docs/release-notes/2-6-0/#v260",
	)
}
