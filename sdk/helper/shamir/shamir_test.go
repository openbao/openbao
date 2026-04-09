// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package shamir

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplit_invalid(t *testing.T) {
	secret := []byte("test")

	_, err := Split(secret, 0, 0)
	require.Error(t, err)

	_, err = Split(secret, 2, 3)
	require.Error(t, err)

	_, err = Split(secret, 1000, 3)
	require.Error(t, err)

	_, err = Split(secret, 10, 1)
	require.Error(t, err)

	_, err = Split(nil, 3, 2)
	require.Error(t, err)
}

func TestSplit(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	require.NoError(t, err)
	require.Len(t, out, 5)

	for _, share := range out {
		require.Len(t, share, len(secret)+1)
	}
}

func TestCombine_invalid(t *testing.T) {
	// Not enough parts
	_, err := Combine(nil)
	require.Error(t, err)

	// Mis-match in length
	parts := [][]byte{
		[]byte("foo"),
		[]byte("ba"),
	}
	_, err = Combine(parts)
	require.Error(t, err)

	// Too short
	parts = [][]byte{
		[]byte("f"),
		[]byte("b"),
	}
	_, err = Combine(parts)
	require.Error(t, err)

	parts = [][]byte{
		[]byte("foo"),
		[]byte("foo"),
	}
	_, err = Combine(parts)
	require.Error(t, err)
}

func TestCombine(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	require.NoError(t, err)

	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := range 5 {
		for j := range 5 {
			if j == i {
				continue
			}
			for k := range 5 {
				if k == i || k == j {
					continue
				}

				parts := [][]byte{out[i], out[j], out[k]}
				recomb, err := Combine(parts)
				require.NoError(t, err)
				require.Equal(t, secret, recomb, "parts: (i:%d, j:%d, k:%d)", i, j, k)
			}
		}
	}
}

func TestField_Add(t *testing.T) {
	require.Equal(t, uint8(0), add(16, 16))
	require.Equal(t, uint8(7), add(3, 4))
}

func TestField_Mult(t *testing.T) {
	require.Equal(t, uint8(9), mult(3, 7))
	require.Equal(t, uint8(0), mult(3, 0))
	require.Equal(t, uint8(0), mult(0, 3))
}

func TestField_Divide(t *testing.T) {
	require.Equal(t, uint8(0), div(0, 7))
	require.Equal(t, uint8(1), div(3, 3))
	require.Equal(t, uint8(2), div(6, 3))
}

func TestPolynomial_Random(t *testing.T) {
	p, err := makePolynomial(42, 2)
	require.NoError(t, err)
	require.Equal(t, uint8(42), p.coefficients[0])
}

func TestPolynomial_Eval(t *testing.T) {
	p, err := makePolynomial(42, 1)
	require.NoError(t, err)

	require.Panics(t, func() { p.evaluate(0) }, "expected panic trying to call p.evaluate(0)")

	out := p.evaluate(1)
	exp := add(42, mult(1, p.coefficients[1]))
	require.Equal(t, exp, out)
}

func TestInterpolate_Rand(t *testing.T) {
	for i := range 256 {
		p, err := makePolynomial(uint8(i), 2)
		require.NoError(t, err)

		x_vals := []uint8{1, 2, 3}
		y_vals := []uint8{p.evaluate(1), p.evaluate(2), p.evaluate(3)}
		out := interpolatePolynomial(x_vals, y_vals, 0)
		require.Equal(t, uint8(i), out)
	}
}
