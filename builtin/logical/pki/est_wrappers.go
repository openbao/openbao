// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
)

// buildEstFrameworkPaths creates EST paths for multiple base patterns:
// - Direct: est/<operation>
// - Role-based: roles/<role>/est/<operation>
// - Well-known: .well-known/est/<operation>
// - Well-known with label: .well-known/est/<label>/<operation>
func buildEstFrameworkPaths(b *backend, patternFunc func(b *backend, pattern string) *framework.Path, estApi string) []*framework.Path {
	var patterns []*framework.Path

	// Ensure estApi starts with /
	if !strings.HasPrefix(estApi, "/") {
		estApi = "/" + estApi
	}

	// Base patterns for EST paths
	basePatterns := []string{
		// Direct EST paths (used internally)
		"est",

		// Role-based EST paths
		"roles/" + framework.GenericNameRegex("role") + "/est",

		// Well-known EST paths (RFC 7030 standard)
		".well-known/est",

		// Well-known EST paths with label (RFC 7030 section 3.2.2)
		".well-known/est/" + framework.GenericNameRegex("label"),
	}

	for _, baseUrl := range basePatterns {
		path := patternFunc(b, baseUrl+estApi)
		patterns = append(patterns, path)
	}

	return patterns
}
