// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import "strings"

// Check whether this request path is a relative path containing . or .. as
// path segments.
func IsRelativePath(path string) bool {
	// We look for two patterns, `.` and `..` as path segments, maintaining
	// that they're a portion of a relative path for the purpose of this
	// comparison. We set a maximum complexity limit to ensure we don't
	// endlessly recurse. We ignore double slashes (//), as they're also
	// ignored by the ACL subsystem and are sometimes unfortunately present
	// in OCSP-as-GET requests.

	// Special cases; the rest all have / as a prefix.
	if path == "." || path == ".." || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}

	// Check for relative path portions at the end of the request path.
	if strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") {
		return true
	}

	for index := range len(path) {
		if path[index] == '/' {
			// Check for relative path portions in the middle.
			if (index+3 <= len(path) && path[index:index+3] == "/./") ||
				(index+4 <= len(path) && path[index:index+4] == "/../") {
				return true
			}
		}
	}

	return false
}
