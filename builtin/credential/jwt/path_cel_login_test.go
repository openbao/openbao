// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func Test_applyCelRole(t *testing.T) {
	tests := []struct {
		name           string
		celRole        celRoleEntry
		claims         map[string]interface{}
		auth           logical.Auth
		validateResult func(t *testing.T, err error, role *jwtRole)
	}{
		{
			name: "Boolean expression, returns true",
			celRole: celRoleEntry{
				AuthProgram: "claims.sub == 'test@example.com'",
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
			},
		},
		{
			name: "Boolean expression, returns false",
			celRole: celRoleEntry{
				AuthProgram: "claims.sub == 'test-admin@example.com'",
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.Error(t, err)
				require.Nil(t, rslt)
			},
		},
		{
			name: "SetPolicies will add some policies",
			celRole: celRoleEntry{
				AuthProgram: `SetPolicies(["policy1", "policy2"])`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, []string{"policy1", "policy2"}, rslt.TokenPolicies)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logicalBackend, _ := getBackend(t)
			b, ok := logicalBackend.(*jwtAuthBackend)
			if !ok {
				t.Fatalf("Expected jwtAuthBackend, got %T", logicalBackend)
			}
			role, err := b.runCelProgram(context.Background(), &tc.celRole, tc.claims)
			if tc.validateResult != nil {
				tc.validateResult(t, err, role)
			}
		})
	}
}
