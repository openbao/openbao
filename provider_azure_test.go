package jwtauth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type azureServer struct {
	t      *testing.T
	server *httptest.Server
}

func newAzureServer(t *testing.T) *azureServer {
	a := new(azureServer)
	a.t = t
	a.server = httptest.NewTLSServer(a)

	return a
}

func (a *azureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Write([]byte(strings.Replace(`
			{
				"issuer": "%s",
				"authorization_endpoint": "%s/auth",
				"token_endpoint": "%s/oauth2/v2.0/token",
				"jwks_uri": "%s/certs",
				"userinfo_endpoint": "%s/userinfo"
			}`, "%s", a.server.URL, -1)))
	case "/getMemberObjects":
		groups := azureGroups{
			Value: []interface{}{"group1", "group2"},
		}
		gBytes, _ := json.Marshal(groups)
		w.Write(gBytes)
	default:
		a.t.Fatalf("unexpected path: %q", r.URL.Path)
	}
}

// getTLSCert returns the certificate for this provider in PEM format
func (a *azureServer) getTLSCert() (string, error) {
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

func TestLogin_fetchGroups(t *testing.T) {

	aServer := newAzureServer(t)
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
			"provider": "azure",
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
		"_claim_names": H{
			"groups": "src1",
		},
		"_claim_sources": H{
			"src1": H{
				"endpoint": aServer.server.URL + "/getMemberObjects",
			},
		},
	}

	// Ensure b.cachedConfig is populated
	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the azure provider
	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	if err != nil {
		t.Fatal(err)
	}

	// Ensure groups are as expected
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsResp, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"group1", "group2"}, groupsResp)
}

func Test_getClaimSources(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		a := &AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			claimNamesField: H{
				role.GroupsClaim: "src1",
			},
			claimSourcesField: H{
				"src1": H{
					"endpoint": "/test/endpoint",
				},
			},
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.NoError(t, err)
		assert.Equal(t, "/test/endpoint", source)
	})

	t.Run("no _claim_names", func(t *testing.T) {
		a := AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			"not_claim_names": "blank",
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.Error(t, err)
		assert.Empty(t, source)
	})

	t.Run("no _claim_sources", func(t *testing.T) {
		a := AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			claimNamesField: H{
				role.GroupsClaim: "src1",
			},
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.Error(t, err)
		assert.Empty(t, source)
	})
}
