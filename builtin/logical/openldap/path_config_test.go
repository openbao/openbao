// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/openbao/openbao/builtin/logical/openldap/client"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestConfig_Create(t *testing.T) {
	type testCase struct {
		createData      *framework.FieldData
		createExpectErr bool

		expectedReadResp *logical.Response
	}

	tests := map[string]testCase{
		"happy path with defaults": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"certificate":     validCertificate,
				"request_timeout": 60,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
					"request_timeout", 60,
				),
			},
		},
		"non-default userattr of uid": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"certificate":     validCertificate,
				"request_timeout": 60,
				"userattr":        "uid",
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
					"request_timeout", 60,
					"userattr", "uid",
				),
			},
		},
		"default userattr for openldap schema": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"certificate":     validCertificate,
				"request_timeout": 60,
				"schema":          client.SchemaOpenLDAP,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
					"request_timeout", 60,
					"userattr", "cn",
					"schema", client.SchemaOpenLDAP,
				),
			},
		},
		"default userattr for ad schema": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"certificate":     validCertificate,
				"request_timeout": 60,
				"schema":          client.SchemaAD,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
					"request_timeout", 60,
					"userattr", "userPrincipalName",
					"schema", client.SchemaAD,
				),
			},
		},
		"default userattr for racf schema": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"certificate":     validCertificate,
				"request_timeout": 60,
				"schema":          client.SchemaRACF,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
					"request_timeout", 60,
					"userattr", "racfid",
					"schema", client.SchemaRACF,
				),
			},
		},
		"minimum config": {
			createData: fieldData(map[string]interface{}{
				"binddn":   "tester",
				"bindpass": "pa$$w0rd",
				"url":      "ldap://138.91.247.105",
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"request_timeout", 90,
				),
			},
		},
		"missing binddn": {
			createData: fieldData(map[string]interface{}{
				"bindpass": "pa$$w0rd",
				"url":      "ldap://138.91.247.105",
			}),
			createExpectErr:  true,
			expectedReadResp: nil,
		},
		"password policy": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"password_policy": "testpolicy",
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"password_policy", "testpolicy",
					"request_timeout", 90,
				),
			},
		},
		"password length": {
			createData: fieldData(map[string]interface{}{
				"binddn":   "tester",
				"bindpass": "pa$$w0rd",
				"url":      "ldap://138.91.247.105",
				"length":   30,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"length", 30,
					"request_timeout", 90,
				),
			},
		},
		"skip initial static rotation set": {
			createData: fieldData(map[string]interface{}{
				"binddn":                           "tester",
				"bindpass":                         "pa$$w0rd",
				"url":                              "ldap://138.91.247.105",
				"skip_static_role_import_rotation": true,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"skip_static_role_import_rotation", true,
					"request_timeout", 90,
				),
			},
		},
		"both password policy and password length": {
			createData: fieldData(map[string]interface{}{
				"binddn":          "tester",
				"bindpass":        "pa$$w0rd",
				"url":             "ldap://138.91.247.105",
				"password_policy": "testpolicy",
				"length":          30,
			}),
			createExpectErr:  true,
			expectedReadResp: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(false)
			defer b.Cleanup(context.Background())

			req := &logical.Request{
				Storage:   storage,
				Operation: logical.CreateOperation,
			}

			resp, err := b.configCreateUpdateOperation(context.Background(), req, test.createData)
			if test.createExpectErr && err == nil {
				t.Fatal("err expected, got nil")
			}
			if !test.createExpectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if resp != nil {
				t.Fatalf("no response expected, got: %#v", resp)
			}

			readReq := &logical.Request{
				Storage: storage,
			}

			resp, err = b.configReadOperation(context.Background(), readReq, nil)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			if !reflect.DeepEqual(resp, test.expectedReadResp) {
				t.Fatalf("Actual: %#v\nExpected: %#v", resp, test.expectedReadResp)
			}
		})
	}
}

func TestConfig_Update(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		data = map[string]interface{}{
			"binddn":      "newtester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["binddn"] != "newtester" {
			t.Fatalf("expected binddn to be %s, got %s", "newtester", resp.Data["binddn"])
		}
	})

	t.Run("missing bindpass", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn": "tester",
			"url":    "ldap://138.91.247.105",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
		if resp != nil {
			t.Fatalf("no response expected, got: %#v", resp)
		}
	})

	t.Run("update retains prior config values in storage", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// certificate is intentionally omitted for the update in order
		// to test that it's value set at creation time is retained.
		data = map[string]interface{}{
			"binddn":   "newtester",
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// Assert that the certificate is retained in storage after the update
		if resp.Data["certificate"] != validCertificate {
			t.Fatalf("expected certificate to be %q after update, got %q",
				validCertificate, resp.Data["certificate"])
		}
	})

	t.Run("update retains prior schema and password_policy values in storage", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		initialSchema := "ad"
		initialPasswordPolicy := "test_policy"

		data := map[string]interface{}{
			"binddn":          "tester",
			"schema":          initialSchema,
			"password_policy": initialPasswordPolicy,
			"bindpass":        "pa$$w0rd",
			"url":             "ldap://138.91.247.105",
			"certificate":     validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// schema and password_policy are intentionally omitted for the update in order
		// to test that their values set at creation time is retained.
		data = map[string]interface{}{
			"binddn":   "newtester",
			"bindpass": "pa$$w0rd",
			"url":      "ldap://138.91.247.105",
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// Assert that schema and password policy are retained in storage after the update
		if resp.Data["schema"] != initialSchema {
			t.Fatalf("expected schema to be %q after update, got %q",
				initialSchema, resp.Data["schema"])
		}

		if resp.Data["password_policy"] != initialPasswordPolicy {
			t.Fatalf("expected password_policy to be %q after update, got %q",
				initialPasswordPolicy, resp.Data["password_policy"])
		}
	})
}

func TestConfig_Delete(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	})
}

func Test_defaultUserAttr(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{
			name:   "default userattr for openldap schema",
			schema: client.SchemaOpenLDAP,
			want:   "cn",
		},
		{
			name:   "default userattr for ad schema",
			schema: client.SchemaAD,
			want:   "userPrincipalName",
		},
		{
			name:   "default userattr for racf schema",
			schema: client.SchemaRACF,
			want:   "racfid",
		},
		{
			name:   "default userattr for unknown schema",
			schema: "unknown",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultUserAttr(tt.schema); got != tt.want {
				t.Errorf("defaultUserAttr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func fieldData(raw map[string]interface{}) *framework.FieldData {
	fields := ldaputil.ConfigFields()
	fields["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "The default password time-to-live.",
	}
	fields["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "The maximum password time-to-live.",
	}
	fields["schema"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     defaultSchema,
		Description: "The desired LDAP schema used when modifying user account passwords.",
	}
	fields["password_policy"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Password policy to use to generate passwords",
	}
	fields["skip_static_role_import_rotation"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Description: "Whether to skip the 'import' rotation.",
	}

	// Deprecated
	fields["length"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     defaultPasswordLength,
		Description: "The desired length of passwords that Vault generates.",
		Deprecated:  true,
	}

	return &framework.FieldData{
		Raw:    raw,
		Schema: fields,
	}
}

func ldapResponseData(vals ...interface{}) map[string]interface{} {
	if len(vals)%2 != 0 {
		panic("must specify values as a multiple of two: key and value")
	}

	m := map[string]interface{}{
		"anonymous_group_search":           false,
		"binddn":                           "",
		"case_sensitive_names":             false,
		"certificate":                      "",
		"connection_timeout":               30,
		"deny_null_bind":                   true,
		"dereference_aliases":              "never",
		"discoverdn":                       false,
		"groupattr":                        "cn",
		"groupdn":                          "",
		"groupfilter":                      "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
		"insecure_tls":                     false,
		"max_page_size":                    0,
		"schema":                           client.SchemaOpenLDAP,
		"skip_static_role_import_rotation": false,
		"starttls":                         false,
		"tls_max_version":                  defaultTLSVersion,
		"tls_min_version":                  defaultTLSVersion,
		"upndomain":                        "",
		"url":                              "",
		"use_token_groups":                 false,
		"userattr":                         "cn",
		"userdn":                           "",
		"userfilter":                       "({{.UserAttr}}={{.Username}})",
		"username_as_alias":                false,
	}

	for i := 0; i < len(vals); i += 2 {
		k := vals[i]
		v := vals[i+1]

		ks, ok := k.(string)
		if !ok {
			panic(fmt.Errorf("key at index %d is not a string", i))
		}
		m[ks] = v
	}
	return m
}
