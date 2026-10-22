// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package sealhint

import (
	"strings"
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/stretchr/testify/require"
)

// TestSanitizeSeals_TrimTrailingNewline verifies the operator-facing fix for
// the "openssl rand -base64 32" trailing-newline failure: the key field is
// trimmed in place and a hint is emitted.
func TestSanitizeSeals_TrimTrailingNewline(t *testing.T) {
	seals := []*configutil.KMS{
		{Type: "static", Config: map[string]string{"current_key": "k123\n"}},
	}
	hints := SanitizeSeals(seals)
	require.Len(t, hints, 1)
	require.Contains(t, hints[0], "current_key")
	require.Equal(t, "k123", seals[0].Config["current_key"])
}

// TestSanitizeSeals_CleanKeyUnchanged verifies a clean key is not touched
// and no hint is emitted.
func TestSanitizeSeals_CleanKeyUnchanged(t *testing.T) {
	seals := []*configutil.KMS{
		{Type: "static", Config: map[string]string{"current_key": "k123"}},
	}
	require.Empty(t, SanitizeSeals(seals))
}

// TestSanitizeSeals_NonStaticSealUntouched verifies non-static seals and
// disabled seals are ignored.
func TestSanitizeSeals_NonStaticSealUntouched(t *testing.T) {
	seals := []*configutil.KMS{
		{Type: "transit", Config: map[string]string{"current_key": "k123\n"}},
		{Type: "static", Disabled: true, Config: map[string]string{"current_key": "k123\n"}},
	}
	require.Empty(t, SanitizeSeals(seals))
}

// TestKeyDiagnostic_Message contains actionable detail: the byte length of
// the offending key field, a whitespace note when present, and the
// recommended one-line key-generation command.
func TestKeyDiagnostic_Message(t *testing.T) {
	msg := KeyDiagnostic(map[string]string{"current_key": "abc\n"})
	require.Contains(t, msg, "current_key")
	require.Contains(t, msg, "3 bytes")
	require.Contains(t, msg, "whitespace")
	require.Contains(t, msg, "openssl rand -base64 32 | tr -d '\\n'")
}

// TestKeyDiagnostic_MissingKeyField reports a missing-key diagnostic.
func TestKeyDiagnostic_MissingKeyField(t *testing.T) {
	msg := KeyDiagnostic(nil)
	require.Contains(t, msg, "missing")
}

// TestKeyDiagnostic_PrevKeyLength verifies the previous_key length is
// reported when both fields are present.
func TestKeyDiagnostic_PrevKeyLength(t *testing.T) {
	msg := KeyDiagnostic(map[string]string{"current_key": "abc", "previous_key": "xyz"})
	require.Contains(t, msg, "current_key")
	require.Contains(t, msg, "previous_key")
	require.True(t, strings.Contains(msg, "3 bytes"), "both 3-byte fields reported")
}
