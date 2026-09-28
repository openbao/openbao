// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

// testHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
func testHTTPServer(
	t *testing.T, handler http.Handler,
) (*api.Config, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}

func init() {
	os.Setenv("BAO_TOKEN", "")
	os.Setenv("VAULT_TOKEN", "")
}

func TestLogin(t *testing.T) {
	passwordEnvVar := "LDAP_PASSWORD"
	allowedPassword := "6hrtL!*bro!ywbQbvDwW"

	content := []byte(allowedPassword)
	tmpfile, err := os.CreateTemp("./", "file-containing-password")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name()) // clean up
	err = os.Setenv(passwordEnvVar, allowedPassword)
	require.NoError(t, err)

	if _, err := tmpfile.Write(content); err != nil {
		t.Fatalf("error writing to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("error closing temp file: %v", err)
	}

	// a response to return if the correct values were passed to login
	authSecret := &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken: "a-client-token",
		},
	}

	authBytes, err := json.Marshal(authSecret)
	require.NoError(t, err)

	handler := func(w http.ResponseWriter, req *http.Request) {
		payload := make(map[string]any)
		err := json.NewDecoder(req.Body).Decode(&payload)
		require.NoError(t, err)
		if payload["password"] == allowedPassword {
			w.Write(authBytes)
		}
	}

	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	config.Address = strings.ReplaceAll(config.Address, "127.0.0.1", "localhost")
	client, err := api.NewClient(config)
	require.NoError(t, err)

	// Password fromFile test
	authFromFile, err := NewLDAPAuth("my-ldap-username", &Password{FromFile: tmpfile.Name()})
	require.NoError(t, err)

	loginRespFromFile, err := client.Auth().Login(t.Context(), authFromFile)
	require.NoError(t, err)

	if loginRespFromFile.Auth == nil || loginRespFromFile.Auth.ClientToken == "" {
		t.Fatal("no authentication info returned by login")
	}

	// Password fromEnv Test
	authFromEnv, err := NewLDAPAuth("my-ldap-username", &Password{FromEnv: passwordEnvVar})
	require.NoError(t, err)

	loginRespFromEnv, err := client.Auth().Login(t.Context(), authFromEnv)
	require.NoError(t, err)

	if loginRespFromEnv.Auth == nil || loginRespFromEnv.Auth.ClientToken == "" {
		t.Fatal("no authentication info returned by login with password from env var")
	}

	// Password fromStr test
	authFromStr, err := NewLDAPAuth("my-ldap-username", &Password{FromString: allowedPassword})
	require.NoError(t, err)

	loginRespFromStr, err := client.Auth().Login(t.Context(), authFromStr)
	require.NoError(t, err)

	if loginRespFromStr.Auth == nil || loginRespFromStr.Auth.ClientToken == "" {
		t.Fatal("no authentication info returned by login with password from string")
	}

	// Empty User Test
	_, err = NewLDAPAuth("", &Password{FromString: allowedPassword})
	if err.Error() != "no user name provided for login" {
		t.Fatalf("Auth object created for empty username: %v", err)
	}

	// Empty Password Test
	_, err = NewLDAPAuth("my-ldap-username", nil)
	if err.Error() != "no password provided for login" {
		t.Fatalf("Auth object created when passing a nil Password struct: %v", err)
	}

	// Auth with Custom MountPath
	ldapMount := WithMountPath("customMount")
	_, err = NewLDAPAuth("my-ldap-username", &Password{FromString: allowedPassword}, ldapMount)
	require.NoError(t, err)
}
