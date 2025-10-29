// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"sync"

	"github.com/openbao/openbao/helper/namespace"
)

// Namespace wraps the base namespace with seal specific state.
type Namespace struct {
	*namespace.Namespace

	// seal is the seal provider for this namespace
	seal           Seal
	sealConfig     *SealConfig
	barrier        SecurityBarrier
	unsealKeys     [][]byte
	unsealProgress int
	unsealNonce    string

	// sealLock protects all seal-related fields above, not shared across namespaces.
	sealLock sync.RWMutex
}

// NewNamespace creates a new Namespace wrapper from a base namespace.
func NewNamespace(ns *namespace.Namespace) *Namespace {
	if ns == nil {
		return nil
	}
	return &Namespace{
		Namespace: ns,
	}
}

// WrapNamespace converts a base namespace to a wrapped Namespace.
func WrapNamespace(baseNS *namespace.Namespace) *Namespace {
	if baseNS == nil {
		return nil
	}
	return &Namespace{
		Namespace: baseNS,
	}
}

// UnwrapNamespace extracts the base namespace from a wrapper..
func UnwrapNamespace(ns *Namespace) *namespace.Namespace {
	if ns == nil {
		return nil
	}
	return ns.Namespace
}
