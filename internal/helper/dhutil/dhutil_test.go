// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dhutil

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	ciphertext, nonce, err := EncryptAES(key, key, key)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.NotEmpty(t, nonce)

	plaintext, err := DecryptAES(key, ciphertext, nonce, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, key)
}
