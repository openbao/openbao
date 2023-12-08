// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !testonly

package vault

import (
	"github.com/lf-edge/openbao/sdk/framework"
)

func (b *SystemBackend) activityWritePath() *framework.Path { return nil }
