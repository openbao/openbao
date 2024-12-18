// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"math/rand"
	"testing"
)

const n = 1024

func TestMemZero(t *testing.T) {
	r := rand.Intn(n)
	b := randbytes(r)
	memzero(b)
	if len(b) != r {
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
