// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !tlsdebug

package tlsdebug

import (
	"crypto/tls"

	"github.com/hashicorp/go-hclog"
)

func Inject(_ hclog.Logger, config *tls.Config) *tls.Config {
	return config
}
