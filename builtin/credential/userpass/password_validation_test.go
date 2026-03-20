// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// passwordFieldSchema returns the minimal FieldData schema needed to exercise
// validatePasswordInput and updateUserPassword. It mirrors the fields declared
// in pathUserPassword so that GetOk behaves identically to production.
func passwordFieldSchema() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"password": {
			Type: framework.TypeString,
		},
		"password_hash": {
			Type: framework.TypeString,
		},
	}
}

// makeFieldData builds a FieldData from a raw map using the password schema.
// It is the test equivalent of the framework populating FieldData from an HTTP request.
func makeFieldData(raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw:    raw,
		Schema: passwordFieldSchema(),
	}
}

// TestValidatePasswordInput_OnlyPassword verifies that providing only the
// plaintext password field is accepted as valid input.
func TestValidatePasswordInput_OnlyPassword(t *testing.T) {
	t.Parallel()

	d := makeFieldData(map[string]interface{}{
		"password": "plaintextpassword",
	})

	err := validatePasswordInput(d)

	require.NoError(t, err,
		"only password present must be accepted as valid input")
}

// TestValidatePasswordInput_OnlyPasswordHash verifies that providing only the
// pre-hashed password field is accepted as valid input.
func TestValidatePasswordInput_OnlyPasswordHash(t *testing.T) {
	t.Parallel()

	hash, err := bcrypt.GenerateFromPassword([]byte("plaintextpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	d := makeFieldData(map[string]interface{}{
		"password_hash": string(hash),
	})

	err = validatePasswordInput(d)

	require.NoError(t, err,
		"only password_hash present must be accepted as valid input")
}

// TestValidatePasswordInput_BothFields verifies that providing both password
// and password_hash in the same request is rejected.
func TestValidatePasswordInput_BothFields(t *testing.T) {
	t.Parallel()

	hash, err := bcrypt.GenerateFromPassword([]byte("plaintextpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	d := makeFieldData(map[string]interface{}{
		"password":      "plaintextpassword",
		"password_hash": string(hash),
	})

	err = validatePasswordInput(d)

	require.Error(t, err,
		"both password and password_hash present must be rejected")
	require.Contains(t, err.Error(), "only one of",
		"error message must indicate mutual exclusion")
}

// TestValidatePasswordInput_NeitherField verifies that providing neither
// password nor password_hash is rejected.
func TestValidatePasswordInput_NeitherField(t *testing.T) {
	t.Parallel()

	d := makeFieldData(map[string]interface{}{})

	err := validatePasswordInput(d)

	require.Error(t, err,
		"neither password nor password_hash present must be rejected")
	require.Contains(t, err.Error(), "must provide either",
		"error message must indicate that one field is required")
}

// TestValidatePasswordInput_EmptyPassword verifies that providing an empty
// string for password is treated as absent and rejected.

func TestValidatePasswordInput_EmptyPassword(t *testing.T) {
	t.Parallel()

	d := makeFieldData(map[string]interface{}{
		"password": "",
	})

	err := validatePasswordInput(d)

	require.Error(t, err,
		"empty password string must be rejected as absent")
	require.Contains(t, err.Error(), "must provide either",
		"error message must indicate that a non-empty credential is required")
}

// TestValidatePasswordInput_EmptyPasswordHash verifies that providing an empty
// string for password_hash is treated as absent and rejected.

func TestValidatePasswordInput_EmptyPasswordHash(t *testing.T) {
	t.Parallel()

	d := makeFieldData(map[string]interface{}{
		"password_hash": "",
	})

	err := validatePasswordInput(d)

	require.Error(t, err,
		"empty password_hash string must be rejected as absent")
	require.Contains(t, err.Error(), "must provide either",
		"error message must indicate that a non-empty credential is required")
}

// TestValidatePasswordInput_EmptyPasswordWithValidHash verifies that providing
// an empty password alongside a valid password_hash accepts the hash as the
// sole credential.

func TestValidatePasswordInput_EmptyPasswordWithValidHash(t *testing.T) {
	t.Parallel()

	hash, err := bcrypt.GenerateFromPassword([]byte("plaintextpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	d := makeFieldData(map[string]interface{}{
		"password":      "",
		"password_hash": string(hash),
	})

	err = validatePasswordInput(d)

	require.NoError(t, err,
		"empty password with valid password_hash must be accepted as password_hash only")
}

// TestValidatePasswordInput_ValidPasswordWithEmptyHash verifies that providing
// a valid password alongside an empty password_hash accepts the password as the
// sole credential.
func TestValidatePasswordInput_ValidPasswordWithEmptyHash(t *testing.T) {
	t.Parallel()

	d := makeFieldData(map[string]interface{}{
		"password":      "plaintextpassword",
		"password_hash": "",
	})

	err := validatePasswordInput(d)

	require.NoError(t, err,
		"valid password with empty password_hash must be accepted as password only")
}

// TestUpdateUserPassword_PlaintextPassword verifies that providing a plaintext
// password causes updateUserPassword to store a valid bcrypt hash on the entry.
func TestUpdateUserPassword_PlaintextPassword(t *testing.T) {
	t.Parallel()

	b, err := Factory(context.Background(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	d := makeFieldData(map[string]interface{}{
		"password": "mysecretpassword",
	})
	userEntry := &UserEntry{}

	userErr, intErr := backendImpl.updateUserPassword(&logical.Request{}, d, userEntry)

	require.NoError(t, intErr,
		"updateUserPassword must not return an internal error for a valid plaintext password")
	require.NoError(t, userErr,
		"updateUserPassword must not return a user error for a valid plaintext password")
	require.NotEmpty(t, userEntry.PasswordHash,
		"PasswordHash must be populated after updateUserPassword succeeds")

	cmpErr := bcrypt.CompareHashAndPassword(userEntry.PasswordHash, []byte("mysecretpassword"))
	require.NoError(t, cmpErr,
		"stored PasswordHash must match the original plaintext password via bcrypt comparison")
}

// TestUpdateUserPassword_ValidBcryptHash verifies that providing a valid pre-hashed
// bcrypt string causes updateUserPassword to store it directly on the entry.
func TestUpdateUserPassword_ValidBcryptHash(t *testing.T) {
	t.Parallel()

	b, err := Factory(context.Background(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	hash, err := bcrypt.GenerateFromPassword([]byte("mysecretpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	d := makeFieldData(map[string]interface{}{
		"password_hash": string(hash),
	})
	userEntry := &UserEntry{}

	userErr, intErr := backendImpl.updateUserPassword(&logical.Request{}, d, userEntry)

	require.NoError(t, intErr,
		"updateUserPassword must not return an internal error for a valid bcrypt hash")
	require.NoError(t, userErr,
		"updateUserPassword must not return a user error for a valid bcrypt hash")
	require.Equal(t, hash, userEntry.PasswordHash,
		"stored PasswordHash must equal the provided bcrypt hash bytes verbatim")

	cmpErr := bcrypt.CompareHashAndPassword(userEntry.PasswordHash, []byte("mysecretpassword"))
	require.NoError(t, cmpErr,
		"stored PasswordHash must match the original plaintext password via bcrypt comparison")
}

// TestUpdateUserPassword_InvalidBcryptHash verifies that providing a string that
// is not a valid bcrypt hash is rejected with a user-facing error.
func TestUpdateUserPassword_InvalidBcryptHash(t *testing.T) {
	t.Parallel()

	b, err := Factory(context.Background(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	d := makeFieldData(map[string]interface{}{
		"password_hash": "notabcrypthash",
	})
	userEntry := &UserEntry{}

	userErr, intErr := backendImpl.updateUserPassword(&logical.Request{}, d, userEntry)

	require.NoError(t, intErr,
		"updateUserPassword must not return an internal error for an invalid bcrypt hash")
	require.Error(t, userErr,
		"updateUserPassword must return a user error when password_hash is not a valid bcrypt hash")
	require.Empty(t, userEntry.PasswordHash,
		"PasswordHash must remain empty when an invalid bcrypt hash is rejected")
}

// TestUpdateUserPassword_BothFields verifies that providing both password and
// password_hash in the same request is rejected before any hash is stored.
func TestUpdateUserPassword_BothFields(t *testing.T) {
	t.Parallel()

	b, err := Factory(context.Background(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	hash, err := bcrypt.GenerateFromPassword([]byte("mysecretpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	d := makeFieldData(map[string]interface{}{
		"password":      "mysecretpassword",
		"password_hash": string(hash),
	})
	userEntry := &UserEntry{}

	userErr, intErr := backendImpl.updateUserPassword(&logical.Request{}, d, userEntry)

	require.NoError(t, intErr,
		"updateUserPassword must not return an internal error when both fields are present")
	require.Error(t, userErr,
		"updateUserPassword must return a user error when both password and password_hash are provided")
	require.Empty(t, userEntry.PasswordHash,
		"PasswordHash must remain empty when input validation rejects the request")
}

// TestUpdateUserPassword_NeitherField verifies that providing neither password
// nor password_hash is rejected before any hash is stored.
func TestUpdateUserPassword_NeitherField(t *testing.T) {
	t.Parallel()

	b, err := Factory(context.Background(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	d := makeFieldData(map[string]interface{}{})
	userEntry := &UserEntry{}

	userErr, intErr := backendImpl.updateUserPassword(&logical.Request{}, d, userEntry)

	require.NoError(t, intErr,
		"updateUserPassword must not return an internal error when neither field is present")
	require.Error(t, userErr,
		"updateUserPassword must return a user error when neither password nor password_hash is provided")
	require.Empty(t, userEntry.PasswordHash,
		"PasswordHash must remain empty when input validation rejects the request")
}
