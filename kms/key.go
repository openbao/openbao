// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// KeyType represents the type of cryptographic key
type KeyType int

const (
	GenericSecretKey KeyType = iota
	AESKey
	PublicRSAKey
	PrivateRSAKey
	// TODO: ECC, etc.
)

// KeyAttributes represents basic key attributes and key usages (allowed operations)
type KeyAttributes struct {
	// TODO: should be a UUID ?
	KeyId     string
	Name      string
	GroupId   string
	KeyType   KeyType
	BitKeyLen uint32
	// TODO - algo ?
	IsPersistent bool
	IsRemovable  bool
	IsSensitive  bool

	// Key usages:
	CanEncrypt                  bool
	CanDecrypt                  bool
	CanWrap                     bool
	CanUnwrap                   bool
	CanSign                     bool
	CanVerify                   bool
	CanDerive                   bool
	IsDerivable                 bool
	IsExportable                bool
	IsExportableWithTrustedOnly bool
	IsTrusted                   bool
}

// Key interface represents a cryptographic key
type Key interface {

	// Close terminates the key
	Close() error

	// Login logs in a user (application) to this specific key
	Login(credentials *Credentials) error

	// GetType returns the type of the given key
	GetType() KeyType

	// GetId returns the Id of the given key
	GetId() string

	// GetName returns the name of the given key
	GetName() string

	// GetGroupId returns the Group Id of the given key
	GetGroupId() string

	// GetPersistence returns the persistence of the given key
	IsPersistent() bool

	// GetSensitivity returns the sensitivity of the given key
	IsSensitive() bool

	// GetLength returns the length in bits of the specified key
	// For a secret key, the length in bits of its value
	// For an RSA key, the length in bits of the modulus
	GetLength() uint32

	// GetAlgorithm returns algorithm information for the key (TODO: define return type)
	GetAlgorithm() interface{}

	// GetKeyAttributes returns the complete key attributes
	GetKeyAttributes() *KeyAttributes
}
