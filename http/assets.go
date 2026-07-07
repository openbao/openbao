// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build ui

package http

import (
	"embed"
	"io/fs"
	"net/http"
)

// content is our static web server content.
//
//go:embed web_ui/*
var uiFS embed.FS

// uiFS is a http Filesystem that serves the generated web UI from the
// "ember-dist" make step
func init() {
	subFS, err := fs.Sub(uiFS, "web_ui")
	if err != nil {
		panic(err)
	}
	uiAssets = http.FS(subFS)
}
