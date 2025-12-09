// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

const (
	// EST Path Prefix
	estPathPrefix = "est/"
)

// estState manages state for EST operations
type estState struct {
	// Future: Add EST-specific state management here
	// For now, EST is simpler than ACME and doesn't require
	// complex state management like nonces, accounts, etc.
}

// NewESTState creates a new EST state manager
func NewESTState() *estState {
	return &estState{}
}
