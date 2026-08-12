// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"strings"
)

// The following variables should be set via ldflags.
var (
	// The git commit being compiled.
	GitCommit   string
	GitDescribe string

	// The date of the commit.
	CommitDate string

	// The full version being compiled, e.g., "v2.7.0" or "v2.7.0-beta1".
	fullVersion = "2.0.0-HEAD"

	// Additional version metadata that will be shown as a version suffix behind
	// a "+" separator in various places. This is a good place for downstream to
	// insert a vendor-specific tag, such as "debian".
	VersionMetadata = ""
)

// The following variables should not be set via ldflags.
var (
	// Deprecated: Backwards-compatibility only, replaced by [CommitDate].
	BuildDate string

	// Whether cgo is enabled or not; set via cgo.go at build time.
	CgoEnabled bool

	// Base version and pre-release version, split out from [fullVersion].
	Version, VersionPrerelease, _ = strings.Cut(strings.TrimSpace(fullVersion), "-")
)

func init() {
	if CommitDate == "" {
		CommitDate = BuildDate
	}
}
