// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/openbao/openbao/sdk/helper/ldaputil"
)

var (
	// ex. "ldap://138.91.247.105"
	rawURL = os.Getenv("TEST_LDAP_URL")
	dn     = os.Getenv("TEST_DN")

	// these can be left blank if the operation performed doesn't require them
	username = os.Getenv("TEST_LDAP_USERNAME")
	password = os.Getenv("TEST_LDAP_PASSWORD")
)

// main executes one call using a simple client pointed at the given instance.
func main() {
	config := newInsecureConfig()
	c := client.New(hclog.NewNullLogger())

	filters := map[*client.Field][]string{
		client.FieldRegistry.DisplayName: {"Sara", "Sarah"},
	}

	entries, err := c.Search(config, config.UserDN, ldap.ScopeBaseObject, filters)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("found %d entries:\n", len(entries))
	for _, entry := range entries {
		fmt.Printf("%+v\n", entry)
	}
}

func newInsecureConfig() *client.Config {
	return &client.Config{
		ConfigEntry: &ldaputil.ConfigEntry{
			UserDN:        dn,
			Certificate:   "",
			InsecureTLS:   true,
			BindPassword:  password,
			TLSMinVersion: "tls12",
			TLSMaxVersion: "tls12",
			Url:           rawURL,
			BindDN:        username,
		},
	}
}
