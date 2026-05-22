package http

import "net/http"

// uiAssets is the file system for UI assets. It is set by the build‑tagged
// files (ui.go or stub_asset.go) to either the real embed.FS or nil.
var uiAssets http.FileSystem

// getUIAssets returns the UI assets file system (may be nil if UI is disabled).
func getUIAssets() http.FileSystem {
	return uiAssets
}
