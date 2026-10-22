// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package sealhint provides operator-facing diagnostics for static seal
// (KMS wrapper "static") key material at server boot and reload time.
//
// The static wrapper's key-length dispatch (in the external
// go-kms-wrapping dependency) does not tolerate leading/trailing
// whitespace: a key generated with the common shell idiom
//
//	openssl rand -base64 32
//
// carries a trailing newline, so its byte length lands outside the
// supported encodings and the server fails to configure its seal. This
// package pre-processes the seal config in place (trimming only
// leading/trailing whitespace, never embedded bytes) and reports an
// actionable diagnostic when the key material still cannot load.
package sealhint

import (
	"fmt"
	"strings"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
)

// keyFields are the static-seal config keys that carry key material.
var keyFields = []string{"current_key", "previous_key"}

// Sanitize trims leading/trailing whitespace from the static-seal key
// fields of every non-disabled seal block in the config (in place). The
// trimmed value is written back so the wrapper sees a clean key. One hint
// string per trimmed field is returned for the caller to emit, so an
// operator can verify the key file was not silently altered in a
// meaningful way.
func SanitizeSeals(seals []*configutil.KMS) []string {
	if seals == nil {
		return nil
	}
	var hints []string
	for _, seal := range seals {
		if seal == nil || seal.Disabled || seal.Type != "static" || seal.Config == nil {
			continue
		}
		for _, field := range keyFields {
			v, ok := seal.Config[field]
			if !ok {
				continue
			}
			trimmed := strings.Trim(v, " \t\r\n")
			if trimmed != v {
				seal.Config[field] = trimmed
				hints = append(hints, fmt.Sprintf(
					"seal: static seal %q key field %q had leading/trailing whitespace; trimmed %d byte(s) before configuring the seal. Verify the key file is intact (a stray byte is fatal).",
					field, field, len(v)-len(trimmed)))
			}
		}
	}
	return hints
}

// KeyDiagnostic builds an actionable, specific message for a failed static
// seal key load. It reports the actual byte length of each key field and
// the encodings the static wrapper accepts, so an operator does not have
// to decode the wrapper's "unknown encoding" error to find the cause.
func KeyDiagnostic(config map[string]string) string {
	if config == nil {
		return "seal: static seal key material is missing; set the current_key field"
	}
	var parts []string
	for _, field := range keyFields {
		v, ok := config[field]
		if !ok {
			continue
		}
		trimmed := strings.Trim(v, " \t\r\n")
		note := ""
		if trimmed != v {
			note = " (contains leading/trailing whitespace, which the static wrapper cannot decode)"
		}
		parts = append(parts, fmt.Sprintf("%q is %d bytes%s", field, len(trimmed), note))
	}
	if len(parts) == 0 {
		parts = append(parts, "no key fields configured")
	}
	return fmt.Sprintf(
		"seal: static seal key load failed; %s. Supported encodings for an AES-256 key: 64 hex chars, 44 standard base64 chars, 43 URL-safe raw base64 chars, or 32 raw bytes. Generate a key without a trailing newline: openssl rand -base64 32 | tr -d '\\n' (then verify: wc -c)",
		strings.Join(parts, "; "))
}
