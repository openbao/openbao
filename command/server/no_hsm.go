// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !hsm

package server

import (
	"github.com/hashicorp/go-hclog"
)

func WarnHSMDeprecated(logger hclog.Logger) {}
