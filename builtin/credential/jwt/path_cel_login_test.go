// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"strings"
	"testing"
	"time"

	sqjwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func Test_runCelProgram(t *testing.T) {
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
				AuthProgram: "{'does': 'this work?'}",
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
				AuthProgram: "{'does': 'this work?'}",
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
		{
			name: "Multiple functions can be called in the same program",
			celRole: celRoleEntry{
				AuthProgram: `
                                        claims.sub == 'test@example.com'
                                        ?
                                          SetUserClaim("sub") &&
                                          SetTTL("5m") &&
                                          SetPolicies(["policy1", "policy2"])
                                        :
                                          false
				`,
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *jwtRole) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "sub", rslt.UserClaim)
				require.Equal(t, "5m0s", rslt.TokenTTL.String())
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

func TestCelRoleAuth(t *testing.T) {
	tests := []struct {
		name          string
		celRole       map[string]interface{}
		jwtClaims     sqjwt.Claims
		wantErr       bool
		errorContains string
	}{
		{
			name: "Subjects match, expect success",
			celRole: map[string]interface{}{
				"name":         "testrole",
				"auth_program": "claims.sub == 'joe.public@example.com' && SetUserClaim('sub')",
			},
			jwtClaims: sqjwt.Claims{
				Subject:   "joe.public@example.com",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
			},
			wantErr: false,
		},
		{
			name: "Subject doesn't match, expect error",
			celRole: map[string]interface{}{
				"name":         "testrole",
				"auth_program": "claims.sub == 'joe.public@example.com' && SetUserClaim('sub')",
			},
			jwtClaims: sqjwt.Claims{
				Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
			},
			wantErr:       true,
			errorContains: "blocked authorization",
		},
		{
			name: "Audience match, expect success",
			celRole: map[string]interface{}{
				"name":            "testrole",
				"auth_program":    "claims.sub == 'joe.public@example.com' && SetUserClaim('sub')",
				"bound_audiences": []string{"https://vault.plugin.auth.jwt.test"},
			},
			jwtClaims: sqjwt.Claims{
				Subject:   "joe.public@example.com",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
			},
			wantErr: false,
		},
		{
			name: "Audience mismatch, expect error",
			celRole: map[string]interface{}{
				"name":            "testrole",
				"auth_program":    "claims.sub == 'joe.public@example.com' && SetUserClaim('sub')",
				"bound_audiences": []string{"https://vault.plugin.auth.jwt.test"},
			},
			jwtClaims: sqjwt.Claims{
				Subject:   "joe.public@example.com",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"not-the-right-audience"},
			},
			wantErr:       true,
			errorContains: "audience claim does not match",
		},
	}

	cfg := testConfig{
		audience:      true,
		jwks:          true,
		defaultLeeway: -1,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := setupBackend(t, cfg)
			role := "testrole"

			// Create the CEL role
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/role/" + role,
				Storage:   storage,
				Data:      tt.celRole,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			privateCl := struct {
				User   string   `json:"https://vault/user"`
				Groups []string `json:"https://vault/groups"`
			}{
				"jeff",
				[]string{"foo", "bar"},
			}

			// Generate JWT with the test claims
			jwtData, _ := getTestJWT(t, ecdsaPrivKey, tt.jwtClaims, privateCl)

			// Attempt login
			loginData := map[string]interface{}{
				"role": "testrole",
				"jwt":  jwtData,
			}
			loginReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/login",
				Storage:   storage,
				Data:      loginData,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			resp, err = b.HandleRequest(context.Background(), loginReq)
			if tt.wantErr {
				if !resp.IsError() {
					t.Fatalf("expected error: %v / %v via JWT: %v", resp, resp.Auth, jwtData)
				}
				if tt.errorContains != "" {
					if !strings.Contains(resp.Error().Error(), tt.errorContains) {
						t.Fatalf("unexpected error: %v, want containing: %q", resp.Error(), tt.errorContains)
					}
				}
			} else {
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("unexpected error: err:%s resp:%#v\n", err, resp)
				}
			}
		})
	}
}
