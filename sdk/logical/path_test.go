// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelativePaths(t *testing.T) {
	for path, result := range map[string]bool{
		// Negative
		"":       false,
		"/":      false,
		"/a":     false,
		"a/":     false,
		"//":     false,
		"///":    false,
		"/a/":    false,
		"aa/":    false,
		"a/a":    false,
		"/aa":    false,
		"/alex":  false,
		"alex/":  false,
		"/alex/": false,

		// Triple or more dots have no special path meaning.
		".../a":      false,
		"..../a":     false,
		"...../a":    false,
		"....../a":   false,
		"a/.../a":    false,
		"a/..../a":   false,
		"a/...../a":  false,
		"a/....../a": false,
		"a/...":      false,
		"a/....":     false,
		"a/.....":    false,
		"a/......":   false,
		"...":        false,
		"....":       false,
		".....":      false,
		"......":     false,

		// Positive
		".":      true,
		"./":     true,
		"..":     true,
		"/./":    true,
		"../":    true,
		"/../":   true,
		"a/.":    true,
		"a/./":   true,
		"a/..":   true,
		"a/../":  true,
		"./a":    true,
		"../a":   true,
		"/./a":   true,
		"/../a":  true,
		"a/./a":  true,
		"a/../a": true,
	} {
		require.Equal(t, result, IsRelativePath(path), "difference for path: %v", path)
	}
}
