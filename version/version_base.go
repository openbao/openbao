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

	// The date of the commit. This will be filled in by the compiler.
	CommitDate string

	// Deprecated, backwards-compatibility only: Replaced by CommitDate
	BuildDate string

	// Whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Filled by Goreleaser
	fullVersion                   = "2.0.0-HEAD"
	Version, VersionPrerelease, _ = strings.Cut(strings.TrimSpace(fullVersion), "-")
	VersionMetadata               = ""
)

func init() {
	if CommitDate == "" {
		CommitDate = BuildDate
	}
}
