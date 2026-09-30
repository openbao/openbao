// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package seal

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvelope(t *testing.T) {
	input := []byte("test")
	env, err := NewEnvelope().Encrypt(input, nil)
	require.NoError(t, err)

	output, err := NewEnvelope().Decrypt(env, nil)
	require.NoError(t, err)

	if !bytes.Equal(input, output) {
		t.Fatalf("expected the same text: expected %s, got %s", string(input), string(output))
	}
}
