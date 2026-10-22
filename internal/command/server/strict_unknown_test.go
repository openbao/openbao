// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUnknownKeyDiagnostic verifies that a bogus top-level key (e.g.
// root_token_id) is detected and surfaced as an "unknown or unsupported
// field" diagnostic naming the field.
func TestUnknownKeyDiagnostic(t *testing.T) {
	cfg, err := ParseConfig("root_token_id = \"foo\"\nstorage { type = \"inmem\" }\n", "diag.hcl")
	require.NoError(t, err)
	errs := cfg.Validate("diag.hcl")
	require.NotEmpty(t, errs, "expected an unknown-field diagnostic")
	found := false
	for _, e := range errs {
		if strings.Contains(e.Problem, "root_token_id") {
			found = true
		}
	}
	require.True(t, found, "diagnostic should name the unknown field root_token_id; got: %v", errs)
}

// TestStrictUnknownKeysParses verifies the opt-in strict_unknown_keys flag
// parses correctly from config.
func TestStrictUnknownKeysParses(t *testing.T) {
	cfg, err := ParseConfig("strict_unknown_keys = true\n", "strict.hcl")
	require.NoError(t, err)
	require.True(t, cfg.StrictUnknownKeys)

	cfg2, err := ParseConfig("strict_unknown_keys = false\n", "strict2.hcl")
	require.NoError(t, err)
	require.False(t, cfg2.StrictUnknownKeys)
}

// TestValidConfigNoDiagnostics verifies a fully-valid config produces no
// unknown-key diagnostics (regression).
func TestValidConfigNoDiagnostics(t *testing.T) {
	cfg, err := ParseConfig("cache_size = 10000\n", "valid.hcl")
	require.NoError(t, err)
	errs := cfg.Validate("valid.hcl")
	require.Empty(t, errs)
}
