// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cassandra

import (
	"context"
	"testing"

	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/stretchr/testify/require"
)

func TestAuthenticator_DefaultAllowList(t *testing.T) {
	c := &cassandraConnectionProducer{Username: "u", Password: "p"}
	auth := c.authenticator()
	require.Equal(t, "u", auth.Username)
	require.Equal(t, "p", auth.Password)
	require.Empty(t, auth.AllowedAuthenticators, "gocql default must be kept")

	_, _, err := auth.Challenge([]byte("org.apache.cassandra.auth.PasswordAuthenticator"))
	require.NoError(t, err)
	_, _, err = auth.Challenge([]byte("com.example.LDAPAuthenticator"))
	require.Error(t, err, "LDAP is not in gocql's default list")
}

func TestAuthenticator_CustomAllowList(t *testing.T) {
	list := []string{"com.example.LDAPAuthenticator", "org.apache.cassandra.auth.PasswordAuthenticator"}
	c := &cassandraConnectionProducer{Username: "u", Password: "p", AllowedAuthenticators: list}
	auth := c.authenticator()
	require.Equal(t, list, auth.AllowedAuthenticators)

	_, _, err := auth.Challenge([]byte("com.example.LDAPAuthenticator"))
	require.NoError(t, err)
	_, _, err = auth.Challenge([]byte("com.example.Unlisted"))
	require.Error(t, err)
}

func TestInitialize_AllowedAuthenticators(t *testing.T) {
	c := new()
	_, err := c.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"hosts":                  "localhost",
			"username":               "u",
			"password":               "p",
			"allowed_authenticators": []string{"com.example.LDAPAuthenticator"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"com.example.LDAPAuthenticator"}, c.AllowedAuthenticators)

	c = new()
	_, err = c.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]any{"hosts": "localhost", "username": "u", "password": "p"},
	})
	require.NoError(t, err)
	require.Empty(t, c.AllowedAuthenticators)
}
