// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type secureauthServer struct {
	t      *testing.T
	server *httptest.Server
}

func newsecureauthServer(t *testing.T) *secureauthServer {
	a := new(secureauthServer)
	a.t = t
	a.server = httptest.NewTLSServer(a)

	return a
}

func (a *secureauthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Write([]byte(strings.ReplaceAll(`
			{
				"issuer": "%s",
				"authorization_endpoint": "%s/auth",
				"token_endpoint": "%s/oauth2/v2.0/token",
				"jwks_uri": "%s/certs",
				"userinfo_endpoint": "%s/userinfo"
			}`, "%s", a.server.URL)))
	default:
		a.t.Fatalf("unexpected path: %q", r.URL.Path)
	}
}

// getTLSCert returns the certificate for this provider in PEM format
func (a *secureauthServer) getTLSCert() (string, error) {
	cert := a.server.Certificate()
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemBuf := new(bytes.Buffer)
	if err := pem.Encode(pemBuf, block); err != nil {
		return "", err
	}

	return pemBuf.String(), nil
}

func TestLogin_secureauth_fetchGroups(t *testing.T) {
	aServer := newsecureauthServer(t)
	aCert, err := aServer.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)
	ctx := context.Background()

	data := map[string]interface{}{
		"oidc_discovery_url":    aServer.server.URL,
		"oidc_discovery_ca_pem": aCert,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider": "secureauth",
		},
	}

	// basic configuration
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v\n", err, resp)
	}

	// set up test role
	data = map[string]interface{}{
		"user_claim":            "email",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v\n", err, resp)
	}

	role := &jwtRole{
		GroupsClaim: "groups",
	}
	allClaims := map[string]interface{}{
		"groups": "a-group,another-group",
	}

	// Ensure b.cachedConfig is populated
	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the secureauth provider
	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	if err != nil {
		t.Fatal(err)
	}

	// Ensure groups are as expected
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsRaw, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)
	assert.NoError(t, err)

	groupsResp, ok := normalizeList(groupsRaw)
	assert.True(t, ok)
	assert.Equal(t, []interface{}{"a-group", "another-group"}, groupsResp)
}
