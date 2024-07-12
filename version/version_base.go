// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"strings"
)

var (
	// The git commit that was compiled. This will be filled in by Goreleaser.
	GitCommit   string
	GitDescribe string

	// The compilation date. This will be filled in by the compiler.
	BuildDate string

	// Whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Filled by Goreleaser
	fullVersion                   = "2.0.0-HEAD"
	Version, VersionPrerelease, _ = strings.Cut(strings.TrimSpace(fullVersion), "-")
	VersionMetadata               = ""
)
