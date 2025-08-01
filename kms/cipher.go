// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// CipherOperation represents the direction of the cipher operation: encrypt or decrypt.
type CipherOperation int

const (
	Encrypt CipherOperation = iota
	Decrypt
)

// CipherAlgorithm represents ciphering algorithms
type CipherAlgorithm int

const (
	Cipher_AES_ECB CipherAlgorithm = iota
	Cipher_AES_CBC
	Cipher_AES_CTR
	Cipher_AES_GCM
	// TODO
)

// Padding represents the padding required by some ciphering algorithms.
type Padding int

const (
	NoPadding    Padding = 0x00
	PKCS5Padding Padding = iota
)

// CipherParameters defines the parameters required by a ciphering operation.
// We might want to specialize this per algorithm (provide CTR counter length, 64 bits, for example, etc.).
type CipherParameters struct {
	Algorithm CipherAlgorithm
	Padding   Padding
	// Note: for encryption operations, the caller should not provide the  IV. Instead, the Cipher will generate a random IV.
	IV []byte
	// Additional authenticated data
	AAD []byte
	// MAC (Authentication Tag) of AEAD algorithms to be provided by the caller for decrypt operations.
	MAC []byte
}

// Cipher interface represents ciphering operations
type Cipher interface {

	// This function performs/continues a multiple-part ciphering operation, processing another data part.
	Update(inputData []byte) (outputData []byte, err error)

	// This function finishes a single or multiple-part ciphering operation, possibly processing the last data part.
	// Note: for encryption operations, the caller should not provide the IV when initalizating the Cipher.
	// Instead, the Cipher will generate a random IV that will be returned here.
	// The MAC (Authentication Tag) is returned by this function when encrypting with AEAD algorithms.
	Close(inputData []byte) (outputData []byte, iv []byte, mac []byte, err error)
}

// CipherFactory creates Cipher instances
type CipherFactory interface {
	// NewCipher creates a new Cipher instance
	NewCipher(operation CipherOperation, key Key, cipherParams *CipherParameters) (Cipher, error)
}
