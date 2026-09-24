// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package salt

import (
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestSalt(t *testing.T) {
	inm := &logical.InmemStorage{}
	conf := &Config{}

	salt, err := NewSalt(t.Context(), inm, conf)
	require.NoError(t, err)

	if !salt.DidGenerate() {
		t.Fatal("expected generation")
	}

	// Verify the salt exists
	out, err := inm.Get(t.Context(), DefaultLocation)
	require.NoError(t, err)
	if out == nil {
		t.Fatal("missing salt")
	}

	// Create a new salt, should restore
	salt2, err := NewSalt(t.Context(), inm, conf)
	require.NoError(t, err)

	if salt2.DidGenerate() {
		t.Fatal("unexpected generation")
	}

	// Check for a match
	if salt.salt != salt2.salt {
		t.Fatalf("salt mismatch: %s %s", salt.salt, salt2.salt)
	}

	// Verify a match
	id := "foobarbaz"
	sid1 := salt.SaltID(id)
	sid2 := salt2.SaltID(id)

	if sid1 != sid2 {
		t.Fatal("mismatch")
	}
}

func TestSaltID(t *testing.T) {
	salt, err := uuid.GenerateUUID()
	require.NoError(t, err)
	id := "foobarbaz"

	sid1 := SaltID(salt, id, SHA1Hash)
	sid2 := SaltID(salt, id, SHA1Hash)

	if len(sid1) != sha1.Size*2 {
		t.Fatalf("Bad len: %d %s", len(sid1), sid1)
	}

	if sid1 != sid2 {
		t.Fatal("mismatch")
	}

	sid1 = SaltID(salt, id, SHA256Hash)
	sid2 = SaltID(salt, id, SHA256Hash)

	if len(sid1) != sha256.Size*2 {
		t.Fatalf("Bad len: %d", len(sid1))
	}

	if sid1 != sid2 {
		t.Fatal("mismatch")
	}
}
