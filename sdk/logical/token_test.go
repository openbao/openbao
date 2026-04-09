// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONSerialization(t *testing.T) {
	tt := TokenTypeDefaultBatch
	s, err := json.Marshal(tt)
	require.NoError(t, err)

	var utt TokenType
	err = json.Unmarshal(s, &utt)
	require.NoError(t, err)
	require.Equal(t, tt, utt)

	utt = TokenTypeDefault
	err = json.Unmarshal([]byte(`"default-batch"`), &utt)
	require.NoError(t, err)
	require.Equal(t, tt, utt)

	// Test on an empty value, which should unmarshal into TokenTypeDefault
	tt = TokenTypeDefault
	err = json.Unmarshal([]byte(`""`), &utt)
	require.NoError(t, err)
	require.Equal(t, tt, utt)
}

// TestCreateClientID verifies that CreateClientID uses the entity ID for a token
// entry if one exists, and creates an appropriate client ID otherwise.
func TestCreateClientID(t *testing.T) {
	entry := TokenEntry{NamespaceID: "namespaceFoo", Policies: []string{"bar", "baz", "foo", "banana"}}
	id, isTWE := entry.CreateClientID()
	require.True(t, isTWE, "TWE token should return true value in isTWE bool")

	expectedIDPlaintext := "banana" + string(SortedPoliciesTWEDelimiter) + "bar" +
		string(SortedPoliciesTWEDelimiter) + "baz" +
		string(SortedPoliciesTWEDelimiter) + "foo" + string(ClientIDTWEDelimiter) + "namespaceFoo"

	hashed := sha256.Sum256([]byte(expectedIDPlaintext))
	expectedID := base64.StdEncoding.EncodeToString(hashed[:])
	require.Equal(t, expectedID, id)

	// Test with entityID
	entry = TokenEntry{EntityID: "entityFoo", NamespaceID: "namespaceFoo", Policies: []string{"bar", "baz", "foo", "banana"}}
	id, isTWE = entry.CreateClientID()
	require.False(t, isTWE, "token with entity should return false value in isTWE bool")
	require.Equal(t, "entityFoo", id, "client ID should be entity ID")

	// Test without namespace
	entry = TokenEntry{Policies: []string{"bar", "baz", "foo", "banana"}}
	id, isTWE = entry.CreateClientID()
	require.True(t, isTWE, "TWE token should return true value in isTWE bool")

	expectedIDPlaintext = "banana" + string(SortedPoliciesTWEDelimiter) + "bar" +
		string(SortedPoliciesTWEDelimiter) + "baz" +
		string(SortedPoliciesTWEDelimiter) + "foo" + string(ClientIDTWEDelimiter)

	hashed = sha256.Sum256([]byte(expectedIDPlaintext))
	expectedID = base64.StdEncoding.EncodeToString(hashed[:])
	require.Equal(t, expectedID, id)

	// Test without policies
	entry = TokenEntry{NamespaceID: "namespaceFoo"}
	id, isTWE = entry.CreateClientID()
	require.True(t, isTWE, "TWE token should return true value in isTWE bool")

	expectedIDPlaintext = "namespaceFoo"

	hashed = sha256.Sum256([]byte(expectedIDPlaintext))
	expectedID = base64.StdEncoding.EncodeToString(hashed[:])
	require.Equal(t, expectedID, id)
}
