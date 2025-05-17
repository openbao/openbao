// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/stretchr/testify/assert"

	"github.com/openbao/openbao/builtin/logical/openldap/ldapifc"
)

func TestSearch(t *testing.T) {
	config := emptyConfig()

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldap: ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	entries, err := client.Search(config, dn, ldap.ScopeBaseObject, filters)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("only one entry was provided, but multiple were found: %+v", entries)
	}
	entry := entries[0]

	result, _ := entry.GetJoined(FieldRegistry.PasswordLastSet)
	if result != "0" {
		t.Fatalf("expected PasswordLastSet of \"0\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.UserPrincipalName)
	if result != "jim@example.com" {
		t.Fatalf("expected UserPrincipalName of \"jim@example.com\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.ObjectClass)
	if result != "top,person,organizationalPerson,user" {
		t.Fatalf("expected ObjectClass of \"top,person,organizationalPerson,user\" but received %q", result)
	}
}

func TestUpdateEntry(t *testing.T) {
	config := emptyConfig()

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: dn,
	}
	conn.ModifyRequestToExpect.Replace("cn", []string{"Blue", "Red"})
	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues := map[*Field][]string{
		FieldRegistry.CommonName: {"Blue", "Red"},
	}

	if err := client.UpdateEntry(config, dn, ldap.ScopeBaseObject, filters, newValues); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePasswordOpenLDAP(t *testing.T) {
	testPass := "hell0$catz*"

	config := emptyConfig()
	config.BindDN = "cats"
	config.BindPassword = "dogs"

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: dn,
	}
	conn.ModifyRequestToExpect.Replace("userPassword", []string{testPass})
	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues, err := GetSchemaFieldRegistry(SchemaOpenLDAP, testPass)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.UpdatePassword(config, dn, ldap.ScopeBaseObject, newValues, filters); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePasswordRACF(t *testing.T) {
	testPass := "hell0$catz*"

	config := emptyConfig()
	config.BindDN = "cats"
	config.BindPassword = "dogs"

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: dn,
	}
	conn.ModifyRequestToExpect.Replace("racfPassword", []string{testPass})
	conn.ModifyRequestToExpect.Replace("racfAttributes", []string{"noexpired"})

	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues, err := GetSchemaFieldRegistry(SchemaRACF, testPass)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.UpdatePassword(config, dn, ldap.ScopeBaseObject, newValues, filters); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePasswordAD(t *testing.T) {
	testPass := "hell0$catz*"
	encodedTestPass, err := formatPassword(testPass)
	if err != nil {
		t.Fatal(err)
	}

	config := emptyConfig()
	config.BindDN = "cats"
	config.BindPassword = "dogs"

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: dn,
	}
	conn.ModifyRequestToExpect.Replace("unicodePwd", []string{encodedTestPass})

	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues, err := GetSchemaFieldRegistry(SchemaAD, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := newValues[FieldRegistry.UnicodePassword]; !ok {
		t.Fatal("Expected unicodePwd field to be populated")
	} else if len(p) != 1 {
		t.Fatalf("Expected exactly one entry for unicodePwd but got %d", len(p))
	} else if p[0] != encodedTestPass {
		t.Fatalf("Expected unicodePwd field equal to %q but got %q", encodedTestPass, p[0])
	}

	if err := client.UpdatePassword(config, dn, ldap.ScopeBaseObject, newValues, filters); err != nil {
		t.Fatal(err)
	}
}

// TestUpdateRootPassword mimics the UpdateRootPassword in the SecretsClient.
// However, this test must be located within this package because when the
// "client" is instantiated below, the "ldapClient" is being added to an
// unexported field.
func TestUpdateRootPassword(t *testing.T) {
	testPass := "hell0$catz*"

	config := emptyConfig()
	config.BindDN = "cats"
	config.BindPassword = "dogs"

	expectedRequest := testSearchRequest()
	expectedRequest.BaseDN = config.BindDN
	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: expectedRequest,
		SearchResultToReturn:  testSearchResult(),
	}

	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
	}
	conn.ModifyRequestToExpect.Replace("userPassword", []string{testPass})
	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{ConnToReturn: conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues, err := GetSchemaFieldRegistry(SchemaOpenLDAP, testPass)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.UpdatePassword(config, config.BindDN, ldap.ScopeBaseObject, newValues, filters); err != nil {
		t.Fatal(err)
	}
}

func emptyConfig() *Config {
	return &Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			UserDN:       "dc=example,dc=com",
			Url:          "ldap://127.0.0.1",
			BindDN:       "cats",
			BindPassword: "cats",
		},
	}
}

func testSearchRequest() *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
		Scope:  ldap.ScopeBaseObject,
		Filter: "(objectClass=*)",
	}
}

func testSearchResult() *ldap.SearchResult {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   FieldRegistry.PasswordLastSet.String(),
						Values: []string{"0"},
					},
					{
						Name:   FieldRegistry.UserPrincipalName.String(),
						Values: []string{"jim@example.com"},
					},
					{
						Name:   FieldRegistry.ObjectClass.String(),
						Values: []string{"top", "person", "organizationalPerson", "user"},
					},
				},
			},
		},
	}
}

func TestToString(t *testing.T) {
	tcs := map[string]struct {
		filters              map[*Field][]string
		expectedFilterString string
	}{
		"no-filters": {
			filters:              nil,
			expectedFilterString: "",
		},
		"single-filter": {
			filters:              map[*Field][]string{FieldRegistry.DomainName: {"bob"}},
			expectedFilterString: "(dn=bob)",
		},
		"two-filters": {
			filters: map[*Field][]string{
				FieldRegistry.DomainName:        {"bob"},
				FieldRegistry.UserPrincipalName: {"Bob@example.net"},
			},
			expectedFilterString: "(&(dn=bob)(userPrincipalName=Bob@example.net))",
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			got := toString(tc.filters)
			assert.Equal(t, tc.expectedFilterString, got)
		})
	}
}
