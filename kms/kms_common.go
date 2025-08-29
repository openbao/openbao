// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// Credentials provides login credentials for a keystore provider
// TODO
type Credentials struct {
	IsAdmin  bool
	UserName string
	Password string
}

// Specific initialization parameters for the current crypto provider.
type CryptoProviderParameters struct {
	KeystoreProvider string
	Credentials      *Credentials
	// TODO: define opaque parameters specific to each crypto provider (or derive specific structure from this).
}
