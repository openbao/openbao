// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !ui

package http

func init() {
	// set uiAssets to nil to indicate the ui is not built in. See
	// http/handler.go
	uiAssets = nil
}
