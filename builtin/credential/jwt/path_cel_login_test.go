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
			name: "Boolean expression true, returns role with no error",
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
			name: "Boolean expression false, returns error",
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
			name: "SetPolicies will add some policies to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetPolicies(["policy1", "policy2"])
					: false`,
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
		{
			name: "SetBoundCIDRs will add some CIDRs to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetBoundCIDRs(["192.168.1.0/24", "10.0.1.1/31"])
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "192.168.1.0/24", rslt.TokenBoundCIDRs[0].String())
				require.Equal(t, "10.0.1.1/31", rslt.TokenBoundCIDRs[1].String())
			},
		},
		{
			name: "SetTTL will add TTL duration to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetTTL("5m")
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "5m0s", rslt.TokenTTL.String())
			},
		},
		{
			name: "SetMaxTTL will add TTL duration to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetMaxTTL("5m")
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "5m0s", rslt.TokenMaxTTL.String())
			},
		},
		{
			name: "SetExplicitMaxTTL will add TTL duration to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetExplicitMaxTTL("5m")
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "5m0s", rslt.TokenExplicitMaxTTL.String())
			},
		},
		{
			name: "SetPeriod will add token period duration to the resulting role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetPeriod("5m")
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "5m0s", rslt.TokenPeriod.String())
			},
		},
		{
			name: "SetNoDefaultPolicy will configure the role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetNoDefaultPolicy(true)
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.True(t, rslt.TokenNoDefaultPolicy)
			},
		},
		{
			name: "SetStrictlyBindIP will configure the role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetStrictlyBindIP(true)
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.True(t, rslt.TokenStrictlyBindIP)
			},
		},
		{
			name: "SetTokenNumUses will configure the role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetTokenNumUses(5)
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, 5, rslt.TokenNumUses)
			},
		},
		{
			name: "SetTokenType will configure the role",
			celRole: celRoleEntry{
				AuthProgram: `claims.sub == 'test@example.com'
					? SetTokenType("default-batch")
					: false`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, logical.TokenTypeDefaultBatch, rslt.TokenType)
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
