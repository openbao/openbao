// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

const n = 1024

// randbytes is used to create a buffer of size n filled with random bytes
func randbytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate %d random bytes: %v", n, err))
	}
	return buf
}

func TestMemZero(t *testing.T) {
	r, err := rand.Int(rand.Reader, big.NewInt(n))
	require.NoError(t, err)
	b := randbytes(int(r.Int64()))
	memzero(b)
	if len(b) != int(r.Int64()) {
		t.Fatalf("buffer has wrong length: %d", len(b))
	}
	for i := range b {
		if b[i] != 0 {
			t.Fatalf("buffer contains nonzero bytes: %v", b)
		}
	}
}

func TestRandBytes(t *testing.T) {
	b := randbytes(n)
	if len(b) != n {
		t.Fatalf("buffer has wrong length: %d", len(b))
	}
	c := 0
	for i := range b {
		if b[i] == 0 {
			c++
		}
	}
	// for large n the probability for a false negative result is very small
	if c == n {
		t.Fatalf("buffer contains zero bytes only: %v", b)
	}
}
