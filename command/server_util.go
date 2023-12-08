// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"github.com/lf-edge/openbao/command/server"
	"github.com/lf-edge/openbao/vault"
)

var (
	adjustCoreConfigForEnt = adjustCoreConfigForEntNoop
	storageSupportedForEnt = checkStorageTypeForEntNoop
)

func adjustCoreConfigForEntNoop(config *server.Config, coreConfig *vault.CoreConfig) {
}

var getFIPSInfoKey = getFIPSInfoKeyNoop

func getFIPSInfoKeyNoop() string {
	return ""
}

func checkStorageTypeForEntNoop(coreConfig *vault.CoreConfig) bool {
	return true
}
