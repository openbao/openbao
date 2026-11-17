// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/openbao/openbao/sdk/v2/joinplugin"
	"github.com/openbao/openbao/v2/internal/builtin/join/static"
)

func main() {
	joinplugin.Serve(&joinplugin.ServeOpts{Factory: static.Factory})
}
