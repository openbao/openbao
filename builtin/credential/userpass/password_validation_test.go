// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestValidatePasswordInput(t *testing.T) {
	validHash, err := bcrypt.GenerateFromPassword([]byte("plaintextpassword"), bcrypt.DefaultCost)
	require.NoError(t, err, "bcrypt must not fail during test setup")

	tests := []struct {
		name         string
		password     string
		passwordHash string
		wantErr      bool
		errContains  string
	}{
		{
			name:     "only password provided",
			password: "plaintextpassword",
		},
		{
			name:         "only password_hash provided",
			passwordHash: string(validHash),
		},
		{
			name:         "empty password with valid hash accepted as hash only",
			password:     "",
			passwordHash: string(validHash),
		},
		{
			name:         "valid password with empty hash accepted as password only",
			password:     "plaintextpassword",
			passwordHash: "",
		},
		{
			name:        "neither field provided",
			wantErr:     true,
			errContains: "must provide either",
		},
		{
			name:        "empty password and empty hash",
			password:    "",
			wantErr:     true,
			errContains: "must provide either",
		},
		{
			name:         "both fields provided",
			password:     "plaintextpassword",
			passwordHash: string(validHash),
			wantErr:      true,
			errContains:  "only one of",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordInput(tc.password, tc.passwordHash)
			if tc.wantErr {
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUpdateUserPassword_PlaintextPassword(t *testing.T) {
	b, err := Factory(t.Context(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	userEntry := &UserEntry{}
	userErr, intErr := backendImpl.updateUserPassword("mysecretpassword", "", userEntry)

	require.NoError(t, intErr)
	require.NoError(t, userErr)
	require.NotEmpty(t, userEntry.PasswordHash)

	require.NoError(t, bcrypt.CompareHashAndPassword(userEntry.PasswordHash, []byte("mysecretpassword")))
}

func TestUpdateUserPassword_ValidBcryptHash(t *testing.T) {
	b, err := Factory(t.Context(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	hash, err := bcrypt.GenerateFromPassword([]byte("mysecretpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)

	userEntry := &UserEntry{}
	userErr, intErr := backendImpl.updateUserPassword("", string(hash), userEntry)

	require.NoError(t, intErr)
	require.NoError(t, userErr)
	require.Equal(t, hash, userEntry.PasswordHash)

	require.NoError(t, bcrypt.CompareHashAndPassword(userEntry.PasswordHash, []byte("mysecretpassword")))
}

func TestUpdateUserPassword_InvalidBcryptHash(t *testing.T) {
	b, err := Factory(t.Context(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	userEntry := &UserEntry{}
	userErr, intErr := backendImpl.updateUserPassword("", "notabcrypthash", userEntry)

	require.NoError(t, intErr)
	require.ErrorContains(t, userErr, "not a valid bcrypt hash")
	require.Empty(t, userEntry.PasswordHash)
}

func TestUpdateUserPassword_BothFields(t *testing.T) {
	b, err := Factory(t.Context(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	hash, err := bcrypt.GenerateFromPassword([]byte("mysecretpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)

	userEntry := &UserEntry{}
	userErr, intErr := backendImpl.updateUserPassword("mysecretpassword", string(hash), userEntry)

	require.NoError(t, intErr)
	require.ErrorContains(t, userErr, "only one of")
	require.Empty(t, userEntry.PasswordHash)
}

func TestUpdateUserPassword_NeitherField(t *testing.T) {
	b, err := Factory(t.Context(), logical.TestBackendConfig())
	require.NoError(t, err)
	backendImpl := b.(*backend)

	userEntry := &UserEntry{}
	userErr, intErr := backendImpl.updateUserPassword("", "", userEntry)

	require.NoError(t, intErr)
	require.ErrorContains(t, userErr, "must provide either")
	require.Empty(t, userEntry.PasswordHash)
}
