// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// SignerParameters defines the parameters required by a signing operation.
type VerifierParameters struct {
	Algorithm SignAlgorithm
	// Signature to be verified
	Signature []byte
}

// Verifier interface represents signature verification operations
type Verifier interface {

	// This function continues a multiple-part verification operation, processing another data part.
	Update(data []byte) error

	// This function finishes a single or multiple-part signature verification operation, possibly processing the last data part, and checking the validity of the signature.
	Close(data []byte) error

	// Alternative: the caller provides the signature to be verified at the end of the operation.
	// This function finishes a single or multiple-part signature verification operation, possibly processing the last data part, and checking the validity of the signature.
	CloseEx(data []byte, signature []byte) error
}

// VerifierFactory creates Verifier instances
type VerifierFactory interface {
	// NewVerifier creates a new Verifier instance for signature verification, using a public key.
	NewVerifier(publicKey Key, verifierParams *VerifierParameters) (Verifier, error)

	// NewMACVerifier creates a new Verifier instance for MAC verification
	NewMACVerifier(key Key, algorithm MAC_Algorithm) (Verifier, error)

	// NewHMACVerifier creates a new Verifier instance for HMAC verification
	NewHMACVerifier(key Key, algorithm HMAC_Algorithm) (Verifier, error)
}
