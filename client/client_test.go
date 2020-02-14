package client

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-openldap/ldapifc"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
)

func TestSearch(t *testing.T) {
	config := emptyConfig()

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldap: ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	dn := "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com"
	entries, err := client.Search(config, dn, filters)
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
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	newValues := map[*Field][]string{
		FieldRegistry.CommonName: {"Blue", "Red"},
	}

	if err := client.UpdateEntry(config, dn, filters, newValues); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePassword(t *testing.T) {
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
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	if err := client.UpdatePassword(config, dn, filters, testPass); err != nil {
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
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.ObjectClass: {"*"},
	}

	if err := client.UpdatePassword(config, config.BindDN, filters, testPass); err != nil {
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
