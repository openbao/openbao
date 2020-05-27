package openldap

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/logical"
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
				"binddn":      "tester",
				"bindpass":    "pa$$w0rd",
				"url":         "ldap://138.91.247.105",
				"certificate": validCertificate,
			}),
			createExpectErr: false,
			expectedReadResp: &logical.Response{
				Data: ldapResponseData(
					"binddn", "tester",
					"url", "ldap://138.91.247.105",
					"certificate", validCertificate,
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
				Storage: storage,
			}

			resp, err := b.configCreateUpdateOperation(context.Background(), req, test.createData)
			if test.createExpectErr && err == nil {
				t.Fatalf("err expected, got nil")
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
		Description: "The desired OpenLDAP schema used when modifying user account passwords.",
	}
	fields["password_policy"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Password policy to use to generate passwords",
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
		"anonymous_group_search": false,
		"binddn":                 "",
		"case_sensitive_names":   false,
		"certificate":            "",
		"deny_null_bind":         true,
		"discoverdn":             false,
		"groupattr":              "cn",
		"groupdn":                "",
		"groupfilter":            "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
		"insecure_tls":           false,
		"starttls":               false,
		"tls_max_version":        defaultTLSVersion,
		"tls_min_version":        defaultTLSVersion,
		"upndomain":              "",
		"url":                    "",
		"use_token_groups":       false,
		"userattr":               "cn",
		"userdn":                 "",
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
