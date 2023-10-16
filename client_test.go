package openldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/hashicorp/vault-plugin-secrets-openldap/ldapifc"
)

func GetTestClient(fake *ldapifc.FakeLDAPConnection) *Client {
	ldapClient := client.NewWithClient(hclog.NewNullLogger(), &ldapifc.FakeLDAPClient{
		ConnToReturn: fake,
	})

	return &Client{ldap: ldapClient}
}

// UpdateDNPassword when the UserAttr is "userPrincipalName"
func Test_UpdateDNPassword_AD_UserPrincipalName(t *testing.T) {
	newPassword := "newpassword"
	conn := &ldapifc.FakeLDAPConnection{
		ModifyRequestToExpect: &ldap.ModifyRequest{
			DN: "CN=Bob,CN=Users,DC=example,DC=net",
		},
		SearchRequestToExpect: &ldap.SearchRequest{
			BaseDN: "cn=users",
			Scope:  ldap.ScopeWholeSubtree,
			Filter: "(&(objectClass=*)(userPrincipalName=bob@example.net))",
		},
		SearchResultToReturn: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "CN=Bob,CN=Users,DC=example,DC=net",
				},
			},
		},
	}

	c := GetTestClient(conn)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          "ldaps://ldap:386",
			UserDN:       "cn=users",
			UPNDomain:    "example.net",
			UserAttr:     "userPrincipalName",
			BindDN:       "username",
			BindPassword: "password",
		},
		Schema: client.SchemaAD,
	}

	// depending on the schema, the password may be formatted, so we leverage this helper function
	fields, err := client.GetSchemaFieldRegistry(config.Schema, newPassword)
	assert.NoError(t, err)
	for k, v := range fields {
		conn.ModifyRequestToExpect.Replace(k.String(), v)
	}

	err = c.UpdateDNPassword(config, "bob", newPassword)
	assert.NoError(t, err)
}

// UpdateDNPassword when the UserAttr is "dn"
func Test_UpdateDNPassword_AD_DN(t *testing.T) {
	newPassword := "newpassword"
	conn := &ldapifc.FakeLDAPConnection{
		ModifyRequestToExpect: &ldap.ModifyRequest{
			DN: "CN=Bob,CN=Users,DC=example,DC=net",
		},
		SearchRequestToExpect: &ldap.SearchRequest{
			BaseDN: "CN=Bob,CN=Users,DC=example,DC=net",
			Scope:  ldap.ScopeBaseObject,
			Filter: "(objectClass=*)",
		},
		SearchResultToReturn: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "CN=Bob,CN=Users,DC=example,DC=net",
				},
			},
		},
	}

	c := GetTestClient(conn)
	config := &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			Url:          "ldaps://ldap:386",
			UserAttr:     "dn",
			BindDN:       "username",
			BindPassword: "password",
		},
		Schema: client.SchemaAD,
	}

	// depending on the schema, the password may be formatted, so we leverage this helper function
	fields, err := client.GetSchemaFieldRegistry(config.Schema, newPassword)
	assert.NoError(t, err)
	for k, v := range fields {
		conn.ModifyRequestToExpect.Replace(k.String(), v)
	}

	err = c.UpdateDNPassword(config, "CN=Bob,CN=Users,DC=example,DC=net", newPassword)
	assert.NoError(t, err)

}
