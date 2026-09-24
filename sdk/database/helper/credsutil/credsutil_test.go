// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credsutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomAlphaNumeric(t *testing.T) {
	s, err := RandomAlphaNumeric(10, true)
	require.NoError(t, err)
	if len(s) != 10 {
		t.Fatalf("Unexpected length of string, expected 10, got string: %s", s)
	}

	s, err = RandomAlphaNumeric(20, true)
	require.NoError(t, err)
	if len(s) != 20 {
		t.Fatalf("Unexpected length of string, expected 20, got string: %s", s)
	}

	if !strings.Contains(s, reqStr) {
		t.Fatalf("Expected %s to contain %s", s, reqStr)
	}

	s, err = RandomAlphaNumeric(20, false)
	require.NoError(t, err)
	if len(s) != 20 {
		t.Fatalf("Unexpected length of string, expected 20, got string: %s", s)
	}

	if strings.Contains(s, reqStr) {
		t.Fatalf("Expected %s not to contain %s", s, reqStr)
	}
}
