// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

const (
	// ShareOverhead is the byte size overhead of each share
	// when using Split on a secret. This is caused by appending
	// a one byte tag to the share.
	ShareOverhead = 1
)

// polynomial represents a polynomial of arbitrary degree
type polynomial struct {
	coefficients []uint8
}

// makePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func makePolynomial(intercept, degree uint8) (polynomial, error) {
	// Create a wrapper
	p := polynomial{
		coefficients: make([]byte, degree+1),
	}

	// Ensure the intercept is set
	p.coefficients[0] = intercept

	// Assign random co-efficients to the polynomial
	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return p, err
	}

	return p, nil
}

// Shuffle X coordinates for use; explicitly exclude x=0 as this results
// in leaking a byte of the secret.
//
// See https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
func shuffledXCoordinates() ([]uint8, error) {
	var result []uint8
	for i := 1; i < 256; i++ {
		result = append(result, uint8(i))
	}

	for i := len(result) - 1; i > 0; i-- {
		// Overkill but useful: rand.Int ensures a uniformly randomly chosen
		// integer between 0 and i-1 (inclusive); if we were to merely read a
		// byte from the RNG and return (byte % i), our results would not be
		// uniformly distributed. Since we're going through the effort of
		// using a CS-PRNG here, we should also ensure our distribution is
		// uniform.
		jI, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		if err != nil {
			return nil, err
		}

		j := int(jI.Int64())
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}

// evaluate returns the value of the polynomial for the given x
func (p *polynomial) evaluate(x uint8) uint8 {
	if x == 0 {
		panic("evaluation at x=0 would leak a byte of the secret")
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = add(mult(out, x), coeff)
	}
	return out
}

// interpolatePolynomial takes N sample points and returns
// the value at a given x using a lagrange interpolation.
func interpolatePolynomial(x_samples, y_samples []uint8, x uint8) uint8 {
	limit := len(x_samples)
	var result, basis uint8
	for i := 0; i < limit; i++ {
		basis = 1
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			num := add(x, x_samples[j])
			denom := add(x_samples[i], x_samples[j])
			term := div(num, denom)
			basis = mult(basis, term)
		}
		group := mult(y_samples[i], basis)
		result = add(result, group)
	}
	return result
}

// div divides two numbers in GF(2^8)
func div(a, b uint8) uint8 {
	if b == 0 {
		// leaks some timing information but we don't care anyways as this
		// should never happen, hence the panic
		panic("divide by zero")
	}

	ret := int(mult(a, inverse(b)))

	// Ensure we return zero if a is zero but aren't subject to timing attacks
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(a, 0), 0, ret)
	return uint8(ret)
}

// inverse calculates the inverse of a number in GF(2^8)
func inverse(a uint8) uint8 {
	// Computing a^-1 is equivalent to computing a^254 in GF(2^8 == 256).
	//
	// This is shorter than a for loop with 6 iterations as it involves 11
	// multiplications due to asymmetry rather than 13.

	// a^1 * a^1 = a^2
	b := mult(a, a)

	// a^1 * a^2 = a^3
	c := mult(a, b)

	// a^3 * a^3 = a^6
	b = mult(c, c)

	// a^6 + a^6 = a^12
	b = mult(b, b)

	// a^12 * a^3 = a^15
	c = mult(b, c)

	// a^12 * a^12 = a^24
	b = mult(b, b)

	// a^24 * a^24 = a^48
	b = mult(b, b)

	// a^48 * a^15 = a^63
	b = mult(b, c)

	// a^63 * a^63 = a^126
	b = mult(b, b)

	// a^126 * a = a^127
	b = mult(a, b)

	// a^127 * a^127 = a^254
	return mult(b, b)
}

// mult multiplies two numbers in GF(2^8)
func mult(a, b uint8) (out uint8) {
	var r uint8 = 0
	var i uint8 = 8

	for i > 0 {
		i--
		r = (-(b >> i & 1) & a) ^ (-(r >> 7) & 0x1B) ^ (r + r)
	}

	return r
}

// add combines two numbers in GF(2^8)
// This can also be used for subtraction since it is symmetric.
func add(a, b uint8) uint8 {
	return a ^ b
}

// Split takes an arbitrarily long secret and generates a `parts`
// number of shares, `threshold` of which are required to reconstruct
// the secret. The parts and threshold must be at least 2, and less
// than 256. The returned shares are each one byte longer than the secret
// as they attach a tag used to reconstruct the secret.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, errors.New("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, errors.New("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, errors.New("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates, err := shuffledXCoordinates()
	if err != nil {
		return nil, err
	}

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	out := make([][]byte, parts)
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = xCoordinates[idx]
	}

	// Construct a random polynomial for each byte of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	for idx, val := range secret {
		p, err := makePolynomial(val, uint8(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}

		// Generate a `parts` number of (x,y) pairs
		// We cheat by encoding the x value once as the final index,
		// so that it only needs to be stored once.
		for i := 0; i < parts; i++ {
			x := xCoordinates[i]
			y := p.evaluate(x)
			out[i][idx] = y
		}
	}

	// Return the encoded secrets
	return out, nil
}

// Combine is used to reverse a Split and reconstruct a secret
// once a `threshold` number of parts are available.
func Combine(parts [][]byte) ([]byte, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, errors.New("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, errors.New("parts must be at least two bytes")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, errors.New("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]byte, firstPartLen-1)

	// Buffer to store the samples
	x_samples := make([]uint8, len(parts))
	y_samples := make([]uint8, len(parts))

	// Set the x value for each sample and ensure no x_sample values are the same,
	// otherwise div() can be unhappy
	checkMap := map[byte]bool{}
	for i, part := range parts {
		samp := part[firstPartLen-1]
		if exists := checkMap[samp]; exists {
			return nil, errors.New("duplicate part detected")
		}
		checkMap[samp] = true
		x_samples[i] = samp
	}

	// Reconstruct each byte
	for idx := range secret {
		// Set the y value for each sample
		for i, part := range parts {
			y_samples[i] = part[idx]
		}

		// Interpolate the polynomial and compute the value at 0
		val := interpolatePolynomial(x_samples, y_samples, 0)

		// Evaluate the 0th value to get the intercept
		secret[idx] = val
	}
	return secret, nil
}
