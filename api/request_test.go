// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestSetJSONBody(t *testing.T) {
	var r Request
	raw := map[string]any{"foo": "bar"}
	require.NoError(t, r.SetJSONBody(raw))

	expected := `{"foo":"bar"}`
	actual := strings.TrimSpace(string(r.BodyBytes))
	if actual != expected {
		t.Fatalf("bad: %s", actual)
	}
}

func TestRequestResetJSONBody(t *testing.T) {
	var r Request
	raw := map[string]any{"foo": "bar"}
	require.NoError(t, r.SetJSONBody(raw))

	require.NoError(t, r.ResetJSONBody())

	buf := make([]byte, len(r.BodyBytes))
	copy(buf, r.BodyBytes)

	expected := `{"foo":"bar"}`
	actual := strings.TrimSpace(string(buf))
	if actual != expected {
		t.Fatalf("bad: actual %s, expected %s", actual, expected)
	}
}
