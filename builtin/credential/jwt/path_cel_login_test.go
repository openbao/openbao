// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"strings"
	"testing"
	"time"

	sqjwt "github.com/go-jose/go-jose/v3/jwt"
	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
	"github.com/stretchr/testify/require"
)

// Test_runCelProgram test private method 'runCelProgram'
func Test_runCelProgram(t *testing.T) {
	tests := []struct {
		name           string
		celRole        celRoleEntry
		claims         map[string]interface{}
		auth           logical.Auth
		validateResult func(t *testing.T, err error, role *pb.Auth)
	}{
		{
			name: "Boolean false will return error",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Expression: "1 == 2",
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.Error(t, err)
				require.Nil(t, rslt)
			},
		},
		{
			name: "String will be returned as error",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Expression: "'something is amiss'",
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.Error(t, err)
				require.Nil(t, rslt)
				require.Contains(t, err.Error(), "something is amiss")
			},
		},
		{
			name: "pb.Auth type can be returned",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Expression: `pb.Auth{display_name: 'newAuth'}`,
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.NoError(t, err)
				require.IsType(t, &pb.Auth{}, rslt)
				require.Equal(t, "newAuth", rslt.DisplayName)
			},
		},
		{
			name: "pb.Auth can have policies to the resulting role",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Expression: `pb.Auth{policies: ['policy1', 'policy2']}`,
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, []string{"policy1", "policy2"}, rslt.Policies)
			},
		},
		{
			name: "pb.Auth BoundCIDRs will add some CIDRs to the resulting role",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Expression: `claims.sub == 'test@example.com'
					? pb.Auth{bound_cidrs: ['192.168.1.0/24', '10.0.1.1/31']}
					: false`,
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "192.168.1.0/24", rslt.BoundCIDRs[0])
				require.Equal(t, "10.0.1.1/31", rslt.BoundCIDRs[1])
			},
		},
		{
			name: "Cel variables can be used in the expression",
			celRole: celRoleEntry{
				CelProgram: celhelper.CelProgram{
					Variables: []celhelper.CelVariable{
						{Name: "is_admin", Expression: "claims.sub == 'test@example.com'"},
					},
					Expression: `is_admin
					? pb.Auth{bound_cidrs: ['192.168.1.0/24', '10.0.1.1/31']}
					: false`,
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.NoError(t, err)
				require.NotNil(t, rslt)
				require.Equal(t, "192.168.1.0/24", rslt.BoundCIDRs[0])
				require.Equal(t, "10.0.1.1/31", rslt.BoundCIDRs[1])
			},
		},
		{
			name: "pb.Auth proto message is validated",
			celRole: celRoleEntry{
				Name: "celRole",
				CelProgram: celhelper.CelProgram{
					Variables: []celhelper.CelVariable{
						{Name: "is_admin", Expression: "claims.sub == 'test@example.com'"},
					},
					Expression: `is_admin
					? pb.Auth{no_field: ['192.168.1.0/24', '10.0.1.1/31']}
					: false`,
				},
			},
			claims: map[string]interface{}{
				"sub":    "test@example.com",
				"groups": []string{"group1", "group2"},
			},
			auth: logical.Auth{},
			validateResult: func(t *testing.T, err error, rslt *pb.Auth) {
				require.Error(t, err)
				require.Nil(t, rslt)
				require.Contains(t, err.Error(), "no such field")
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
			role, err := b.runCelProgram(context.Background(), logical.UpdateOperation, &tc.celRole, tc.claims)
			if tc.validateResult != nil {
				tc.validateResult(t, err, role)
			}
		})
	}
}

// TestCelRoleAuth tests the path_cel_role and path_cel_login endpoints
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
				"name": "testrole",
				"cel_program": map[string]interface{}{"expression": `claims.sub == 'joe.public@example.com' 
					? pb.Auth{display_name: 'newAuth'} 
					: false`},
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
				"name":        "testrole",
				"cel_program": map[string]interface{}{"expression": "claims.sub == 'joe.public@example.com' ? pb.Auth{display_name: 'newAuth'} : false"},
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
				"cel_program":     map[string]interface{}{"expression": "claims.sub == 'joe.public@example.com' ? pb.Auth{display_name: 'newAuth'} : false"},
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
				"cel_program":     map[string]interface{}{"expression": "claims.sub == 'joe.public@example.com'"},
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
