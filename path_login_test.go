package jwtauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/square/go-jose.v2"
	sqjwt "gopkg.in/square/go-jose.v2/jwt"
)

type H map[string]interface{}

type testConfig struct {
	oidc           bool
	role_type_oidc bool
	audience       bool
	boundClaims    bool
	boundCIDRs     bool
	jwks           bool
	defaultLeeway  int
	expLeeway      int
	nbfLeeway      int
	groupsClaim    string
}

type closeableBackend struct {
	logical.Backend

	closeServerFunc func()
}

func setupBackend(t *testing.T, cfg testConfig) (closeableBackend, logical.Storage) {
	cb := closeableBackend{
		closeServerFunc: func() {},
	}

	b, storage := getBackend(t)

	if cfg.groupsClaim == "" {
		cfg.groupsClaim = "https://vault/groups"
	}

	var data map[string]interface{}
	if cfg.oidc {
		data = map[string]interface{}{
			"bound_issuer":       "https://team-vault.auth0.com/",
			"oidc_discovery_url": "https://team-vault.auth0.com/",
		}
	} else {
		if !cfg.jwks {
			data = map[string]interface{}{
				"bound_issuer":           "https://team-vault.auth0.com/",
				"jwt_validation_pubkeys": ecdsaPubKey,
			}
		} else {
			p := newOIDCProvider(t)
			cb.closeServerFunc = p.server.Close

			cert, err := p.getTLSCert()
			if err != nil {
				t.Fatal(err)
			}

			data = map[string]interface{}{
				"jwks_url":    p.server.URL + "/certs",
				"jwks_ca_pem": cert,
			}
		}
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"role_type":     "jwt",
		"bound_subject": "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		"user_claim":    "https://vault/user",
		"groups_claim":  cfg.groupsClaim,
		"policies":      "test",
		"period":        "3s",
		"ttl":           "1s",
		"num_uses":      12,
		"max_ttl":       "5s",
		"claim_mappings": map[string]string{
			"first_name":   "name",
			"/org/primary": "primary_org",
		},
	}
	if cfg.role_type_oidc {
		data["role_type"] = "oidc"
		data["allowed_redirect_uris"] = "http://127.0.0.1"
	}
	if cfg.audience {
		data["bound_audiences"] = []string{"https://vault.plugin.auth.jwt.test", "another_audience"}
	}
	if cfg.boundClaims {
		data["bound_claims"] = map[string]interface{}{
			"color": "green",
		}
	}
	if cfg.boundCIDRs {
		data["bound_cidrs"] = "127.0.0.42"
	}

	data["clock_skew_leeway"] = cfg.defaultLeeway
	data["expiration_leeway"] = cfg.expLeeway
	data["not_before_leeway"] = cfg.nbfLeeway

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cb.Backend = b

	return cb, storage
}

func getTestJWT(t *testing.T, privKey string, cl sqjwt.Claims, privateCl interface{}) (string, *ecdsa.PrivateKey) {
	t.Helper()
	var key *ecdsa.PrivateKey
	block, _ := pem.Decode([]byte(privKey))
	if block != nil {
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sqjwt.Signed(sig).Claims(cl).Claims(privateCl).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return raw, key
}

func getTestOIDC(t *testing.T) string {
	if os.Getenv("OIDC_CLIENT_SECRET") == "" {
		t.SkipNow()
	}

	url := "https://team-vault.auth0.com/oauth/token"
	payload := strings.NewReader("{\"client_id\":\"r3qXcK2bix9eFECzsU3Sbmh0K16fatW6\",\"client_secret\":\"" + os.Getenv("OIDC_CLIENT_SECRET") + "\",\"audience\":\"https://vault.plugin.auth.jwt.test\",\"grant_type\":\"client_credentials\"}")
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	type a0r struct {
		AccessToken string `json:"access_token"`
	}
	var out a0r
	err = json.Unmarshal(body, &out)
	if err != nil {
		t.Fatal(err)
	}

	return out.AccessToken
}

func TestLogin_JWT(t *testing.T) {
	testLogin_JWT(t, false)
	testLogin_JWT(t, true)
}

func testLogin_JWT(t *testing.T, jwks bool) {
	// Test role_type oidc
	{
		cfg := testConfig{
			role_type_oidc: true,
			audience:       true,
			jwks:           jwks,
		}
		b, storage := setupBackend(t, cfg)

		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatal("expected error")
		}
		if !strings.Contains(resp.Error().Error(), "role with oidc role_type is not allowed") {
			t.Fatalf("unexpected error: %v", resp.Error())
		}
	}

	// Test missing audience
	{

		cfg := testConfig{
			jwks: jwks,
		}
		b, storage := setupBackend(t, cfg)

		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatal("expected error")
		}
		if !strings.Contains(resp.Error().Error(), "no audiences bound to the role") {
			t.Fatalf("unexpected error: %v", resp.Error())
		}
	}

	// test valid inputs
	{
		// run test with and without bound_cidrs configured
		for _, useBoundCIDRs := range []bool{false, true} {
			cfg := testConfig{
				audience:    true,
				boundClaims: true,
				boundCIDRs:  useBoundCIDRs,
				jwks:        jwks,
			}
			b, storage := setupBackend(t, cfg)

			cl := sqjwt.Claims{
				Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
			}

			type orgs struct {
				Primary string `json:"primary"`
			}

			privateCl := struct {
				User      string   `json:"https://vault/user"`
				Groups    []string `json:"https://vault/groups"`
				FirstName string   `json:"first_name"`
				Org       orgs     `json:"org"`
				Color     string   `json:"color"`
			}{
				"jeff",
				[]string{"foo", "bar"},
				"jeff2",
				orgs{"engineering"},
				"green",
			}

			jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

			data := map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtData,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.42",
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp == nil {
				t.Fatal("got nil response")
			}
			if resp.IsError() {
				t.Fatalf("got error: %v", resp.Error())
			}

			auth := resp.Auth
			switch {
			case len(auth.Policies) != 1 || auth.Policies[0] != "test":
				t.Fatal(auth.Policies)
			case auth.Alias.Name != "jeff":
				t.Fatal(auth.Alias.Name)
			case len(auth.GroupAliases) != 2 || auth.GroupAliases[0].Name != "foo" || auth.GroupAliases[1].Name != "bar":
				t.Fatal(auth.GroupAliases)
			case auth.Period != 3*time.Second:
				t.Fatal(auth.Period)
			case auth.TTL != time.Second:
				t.Fatal(auth.TTL)
			case auth.MaxTTL != 5*time.Second:
				t.Fatal(auth.MaxTTL)
			}

			// check alias metadata
			metadata := map[string]string{
				"name":        "jeff2",
				"primary_org": "engineering",
			}

			if diff := deep.Equal(auth.Alias.Metadata, metadata); diff != nil {
				t.Fatal(diff)
			}

			// check token metadata
			metadata["role"] = "plugin-test"
			if diff := deep.Equal(auth.Metadata, metadata); diff != nil {
				t.Fatal(diff)
			}
		}
	}

	cfg := testConfig{
		audience:    true,
		boundClaims: true,
		jwks:        jwks,
	}
	b, storage := setupBackend(t, cfg)

	// test invalid bound claim
	{
		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		type orgs struct {
			Primary string `json:"primary"`
		}

		privateCl := struct {
			User      string   `json:"https://vault/user"`
			Groups    []string `json:"https://vault/groups"`
			FirstName string   `json:"first_name"`
			Org       orgs     `json:"org"`
		}{
			"jeff",
			[]string{"foo", "bar"},
			"jeff2",
			orgs{"engineering"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.IsError() {
			t.Fatalf("expected error, got: %v", resp.Data)
		}
	}

	// test bad signature
	{
		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, badPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad issuer
	{
		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-fault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad audience
	{
		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://fault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad subject
	{
		cl := sqjwt.Claims{
			Subject:   "p3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test missing user value
	{
		cl := sqjwt.Claims{
			Subject:  "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:   "https://team-vault.auth0.com/",
			Expiry:   sqjwt.NewNumericDate(time.Now().Add(5 * time.Second)),
			Audience: sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, struct{}{})

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test invalid address
	{
		cfg := testConfig{
			boundCIDRs: true,
			jwks:       jwks,
		}
		b, storage := setupBackend(t, cfg)

		cl := sqjwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    "https://team-vault.auth0.com/",
			NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		}

		privateCl := struct {
			User   string   `json:"https://vault/user"`
			Groups []string `json:"https://vault/groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role": "plugin-test",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.99",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != logical.ErrPermissionDenied {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatal("expected nil response")
		}
	}

	// test bad role name
	{
		jwtData, _ := getTestJWT(t, ecdsaPrivKey, sqjwt.Claims{}, struct{}{})

		data := map[string]interface{}{
			"role": "plugin-test-bad",
			"jwt":  jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
		if resp.Error().Error() != `role "plugin-test-bad" could not be found` {
			t.Fatalf("unexpected error: %s", resp.Error())
		}
	}
}

func TestLogin_Leeways(t *testing.T) {
	testLogin_ExpiryClaims(t, true)
	testLogin_ExpiryClaims(t, false)
	testLogin_NotBeforeClaims(t, true)
	testLogin_NotBeforeClaims(t, false)
}

func testLogin_ExpiryClaims(t *testing.T, jwks bool) {
	tests := []struct {
		Context       string
		Valid         bool
		JWKS          bool
		IssuedAt      time.Time
		NotBefore     time.Time
		Expiration    time.Time
		DefaultLeeway int
		ExpLeeway     int
	}{
		// iat, auto clock_skew_leeway (60s), auto expiration leeway (150s)
		{"auto expire leeway using iat with auto clock_skew_leeway", true, jwks, time.Now().Add(-205 * time.Second), time.Time{}, time.Time{}, 0, 0},
		{"expired auto expire leeway using iat with auto clock_skew_leeway", false, jwks, time.Now().Add(-215 * time.Second), time.Time{}, time.Time{}, 0, 0},

		// iat, clock_skew_leeway (10s), auto expiration leeway (150s)
		{"auto expire leeway using iat with custom clock_skew_leeway", true, jwks, time.Now().Add(-150 * time.Second), time.Time{}, time.Time{}, 10, 0},
		{"expired auto expire leeway using iat with custom clock_skew_leeway", false, jwks, time.Now().Add(-165 * time.Second), time.Time{}, time.Time{}, 10, 0},

		// iat, no clock_skew_leeway (0s), auto expiration leeway (150s)
		{"auto expire leeway using iat with no clock_skew_leeway", true, jwks, time.Now().Add(-145 * time.Second), time.Time{}, time.Time{}, -1, 0},
		{"expired auto expire leeway using iat with no clock_skew_leeway", false, jwks, time.Now().Add(-155 * time.Second), time.Time{}, time.Time{}, -1, 0},

		// nbf, auto clock_skew_leeway (60s), auto expiration leeway (150s)
		{"auto expire leeway using nbf with auto clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-205 * time.Second), time.Time{}, 0, 0},
		{"expired auto expire leeway using nbf with auto clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-215 * time.Second), time.Time{}, 0, 0},

		// nbf, clock_skew_leeway (10s), auto expiration leeway (150s)
		{"auto expire leeway using nbf with custom clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-145 * time.Second), time.Time{}, 10, 0},
		{"expired auto expire leeway using nbf with custom clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-165 * time.Second), time.Time{}, 10, 0},

		// nbf, no clock_skew_leeway (0s), auto expiration leeway (150s)
		{"auto expire leeway using nbf with no clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-145 * time.Second), time.Time{}, -1, 0},
		{"expired auto expire leeway using nbf with no clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-155 * time.Second), time.Time{}, -1, 0},

		// iat, auto clock_skew_leeway (60s), custom expiration leeway (10s)
		{"custom expire leeway using iat with clock_skew_leeway", true, jwks, time.Now().Add(-65 * time.Second), time.Time{}, time.Time{}, 0, 10},
		{"expired custom expire leeway using iat with clock_skew_leeway", false, jwks, time.Now().Add(-75 * time.Second), time.Time{}, time.Time{}, 0, 10},

		// iat, clock_skew_leeway (10s), custom expiration leeway (10s)
		{"custom expire leeway using iat with clock_skew_leeway", true, jwks, time.Now().Add(-5 * time.Second), time.Time{}, time.Time{}, 10, 10},
		{"expired custom expire leeway using iat with clock_skew_leeway", false, jwks, time.Now().Add(-25 * time.Second), time.Time{}, time.Time{}, 10, 10},

		// iat, clock_skew_leeway (10s), no expiration leeway (10s)
		{"no expire leeway using iat with clock_skew_leeway", true, jwks, time.Now().Add(-5 * time.Second), time.Time{}, time.Time{}, 10, -1},
		{"expired no expire leeway using iat with clock_skew_leeway", false, jwks, time.Now().Add(-15 * time.Second), time.Time{}, time.Time{}, 10, -1},

		// nbf, default clock_skew_leeway (60s), custom expiration leeway (10s)
		{"custom expire leeway using nbf with clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-65 * time.Second), time.Time{}, 0, 10},
		{"expired custom expire leeway using nbf with clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-75 * time.Second), time.Time{}, 0, 10},

		// nbf, clock_skew_leeway (10s), custom expiration leeway (0s)
		{"custom expire leeway using nbf with clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-5 * time.Second), time.Time{}, 10, 10},
		{"expired custom expire leeway using nbf with clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-25 * time.Second), time.Time{}, 10, 10},

		// nbf, clock_skew_leeway (10s), no expiration leeway (0s)
		{"no expire leeway using nbf with clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-5 * time.Second), time.Time{}, 10, -1},
		{"no expire leeway using nbf with clock_skew_leeway", true, jwks, time.Time{}, time.Now().Add(-5 * time.Second), time.Time{}, 10, -100},
		{"expired no expire leeway using nbf with clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-15 * time.Second), time.Time{}, 10, -1},
		{"expired no expire leeway using nbf with clock_skew_leeway", false, jwks, time.Time{}, time.Now().Add(-15 * time.Second), time.Time{}, 10, -100},
	}

	for i, tt := range tests {
		cfg := testConfig{
			audience:      true,
			jwks:          tt.JWKS,
			defaultLeeway: tt.DefaultLeeway,
			expLeeway:     tt.ExpLeeway,
		}
		b, storage := setupBackend(t, cfg)
		req := setupLogin(t, tt.IssuedAt, tt.Expiration, tt.NotBefore, b, storage)

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}

		if tt.Valid && resp.IsError() {
			t.Fatalf("[test %d: %s jws: %v] unexpected error: %s", i, tt.Context, tt.JWKS, resp.Error())
		} else if !tt.Valid && !resp.IsError() {
			t.Fatalf("[test %d: %s jws: %v] expected token expired error, got : %v", i, tt.Context, tt.JWKS, *resp)
		}
		b.closeServerFunc()
	}
}

func testLogin_NotBeforeClaims(t *testing.T, jwks bool) {
	tests := []struct {
		Context       string
		Valid         bool
		JWKS          bool
		IssuedAt      time.Time
		NotBefore     time.Time
		Expiration    time.Time
		DefaultLeeway int
		NBFLeeway     int
	}{
		// iat, auto clock_skew_leeway (60s), no nbf leeway (0)
		{"no nbf leeway using iat with auto clock_skew_leeway", true, jwks, time.Now().Add(55 * time.Second), time.Time{}, time.Now(), 0, -1},
		{"not yet valid no nbf leeway using iat with auto clock_skew_leeway", false, jwks, time.Now().Add(65 * time.Second), time.Time{}, time.Now(), 0, -1},

		// iat, clock_skew_leeway (10s), no nbf leeway (0s)
		{"no nbf leeway using iat with custom clock_skew_leeway", true, jwks, time.Now().Add(5 * time.Second), time.Time{}, time.Time{}, 10, -1},
		{"not yet valid no nbf leeway using iat with custom clock_skew_leeway", false, jwks, time.Now().Add(15 * time.Second), time.Time{}, time.Time{}, 10, -1},

		// iat, no clock_skew_leeway (0s), nbf leeway (5s)
		{"nbf leeway using iat with no clock_skew_leeway", true, jwks, time.Now(), time.Time{}, time.Time{}, -1, 5},
		{"not yet valid nbf leeway using iat with no clock_skew_leeway", false, jwks, time.Now().Add(6 * time.Second), time.Time{}, time.Time{}, -1, 5},

		// exp, auto clock_skew_leeway (60s), auto nbf leeway (150s)
		{"auto nbf leeway using exp with auto clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(205 * time.Second), 0, 0},
		{"not yet valid auto nbf leeway using exp with auto clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(215 * time.Second), 0, 0},

		// exp, clock_skew_leeway (10s), auto nbf leeway (150s)
		{"auto nbf leeway using exp with custom clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(150 * time.Second), 10, 0},
		{"not yet valid auto nbf leeway using exp with custom clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(165 * time.Second), 10, 0},

		// exp, no clock_skew_leeway (0s), auto nbf leeway (150s)
		{"auto nbf leeway using exp with no clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(145 * time.Second), -1, 0},
		{"not yet valid auto nbf leeway using exp with no clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(152 * time.Second), -1, 0},

		// exp, auto clock_skew_leeway (60s), custom nbf leeway (10s)
		{"custom nbf leeway using exp with auto clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(65 * time.Second), 0, 10},
		{"not yet valid custom nbf leeway using exp with auto clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(75 * time.Second), 0, 10},

		// exp, clock_skew_leeway (10s), custom nbf leeway (10s)
		{"custom nbf leeway using exp with custom clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(15 * time.Second), 10, 10},
		{"not yet valid custom nbf leeway using exp with custom clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(25 * time.Second), 10, 10},

		// exp, no clock_skew_leeway (0s), custom nbf leeway (5s)
		{"custom nbf leeway using exp with no clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(3 * time.Second), -1, 5},
		{"custom nbf leeway using exp with no clock_skew_leeway", true, jwks, time.Time{}, time.Time{}, time.Now().Add(3 * time.Second), -100, 5},
		{"not yet valid custom nbf leeway using exp with no clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(7 * time.Second), -1, 5},
		{"not yet valid custom nbf leeway using exp with no clock_skew_leeway", false, jwks, time.Time{}, time.Time{}, time.Now().Add(7 * time.Second), -100, 5},
	}

	for i, tt := range tests {
		cfg := testConfig{
			audience:      true,
			jwks:          tt.JWKS,
			defaultLeeway: tt.DefaultLeeway,
			expLeeway:     0,
			nbfLeeway:     tt.NBFLeeway,
		}
		b, storage := setupBackend(t, cfg)
		req := setupLogin(t, tt.IssuedAt, tt.Expiration, tt.NotBefore, b, storage)

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}

		if tt.Valid && resp.IsError() {
			t.Fatalf("[test %d: %s] unexpected error: %s", i, tt.Context, resp.Error())
		} else if !tt.Valid && !resp.IsError() {
			t.Fatalf("[test %d: %s jws: %v] expected token not valid yet error, got : %v", i, tt.Context, *resp, tt.JWKS)
		}
		b.closeServerFunc()
	}
}

func TestLogin_JWTSupportedAlgs(t *testing.T) {
	tests := []struct {
		name             string
		jwtSupportedAlgs []string
		wantErr          bool
	}{
		{
			name: "JWT auth with empty signing algorithms",
		},
		{
			name:             "JWT auth with valid signing algorithm",
			jwtSupportedAlgs: []string{string(jwt.ES256)},
		},
		{
			name:             "JWT auth with valid signing algorithms",
			jwtSupportedAlgs: []string{string(jwt.RS256), string(jwt.ES256), string(jwt.EdDSA)},
		},
		{
			name:             "JWT auth with invalid signing algorithm",
			jwtSupportedAlgs: []string{string(jwt.RS256)},
			wantErr:          true,
		},
		{
			name:             "JWT auth with invalid signing algorithms",
			jwtSupportedAlgs: []string{string(jwt.RS256), string(jwt.ES512), string(jwt.EdDSA)},
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := getBackend(t)

			// Configure the backend with an ES256 public key
			data := map[string]interface{}{
				"jwt_validation_pubkeys": ecdsaPubKey,
				"jwt_supported_algs":     tt.jwtSupportedAlgs,
			}
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      data,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.False(t, resp.IsError())

			// Configure a JWT role
			data = map[string]interface{}{
				"role_type":       "jwt",
				"bound_audiences": []string{"https://vault.plugin.auth.jwt.test"},
				"user_claim":      "email",
			}
			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/plugin-test",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.False(t, resp.IsError())

			// Sign a JWT with the related ES256 private key
			cl := sqjwt.Claims{
				Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
				Issuer:    "https://team-vault.auth0.com/",
				NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
				Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
			}
			privateCl := struct {
				Email string `json:"email"`
			}{
				"vault@hashicorp.com",
			}
			jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

			// Authenticate using the signed JWT
			data = map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtData,
			}
			req = &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			if tt.wantErr {
				require.True(t, resp.IsError())
				return
			}
			require.NoError(t, err)
			require.False(t, resp.IsError())
		})
	}
}

func setupLogin(t *testing.T, iat, exp, nbf time.Time, b logical.Backend, storage logical.Storage) *logical.Request {
	cl := sqjwt.Claims{
		Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
		Issuer:    "https://team-vault.auth0.com/",
		Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		IssuedAt:  sqjwt.NewNumericDate(iat),
		Expiry:    sqjwt.NewNumericDate(exp),
		NotBefore: sqjwt.NewNumericDate(nbf),
	}

	type orgs struct {
		Primary string `json:"primary"`
	}
	privateCl := struct {
		User   string   `json:"https://vault/user"`
		Groups []string `json:"https://vault/groups"`
		Org    orgs     `json:"org"`
		Color  string   `json:"color"`
	}{
		"foobar",
		[]string{"foo", "bar"},
		orgs{"engineering"},
		"green",
	}

	jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	return req
}

func TestLogin_OIDC(t *testing.T) {
	cfg := testConfig{
		oidc:          true,
		audience:      true,
		defaultLeeway: -1,
	}
	b, storage := setupBackend(t, cfg)

	jwtData := getTestOIDC(t)

	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error: %v", resp.Error())
	}

	auth := resp.Auth
	switch {
	case len(auth.Policies) != 1 || auth.Policies[0] != "test":
		t.Fatal(auth.Policies)
	case auth.Alias.Name != "jeff":
		t.Fatal(auth.Alias.Name)
	case len(auth.GroupAliases) != 2 || auth.GroupAliases[0].Name != "foo" || auth.GroupAliases[1].Name != "bar":
		t.Fatal(auth.GroupAliases)
	case auth.Period != 3*time.Second:
		t.Fatal(auth.Period)
	case auth.TTL != time.Second:
		t.Fatal(auth.TTL)
	case auth.MaxTTL != 5*time.Second:
		t.Fatal(auth.MaxTTL)
	}
}

func TestLogin_NestedGroups(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"bound_issuer":           "https://team-vault.auth0.com/",
		"jwt_validation_pubkeys": ecdsaPubKey,
		"jwt_supported_algs":     string(jwt.ES256),
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": "https://vault.plugin.auth.jwt.test",
		"bound_subject":   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		"user_claim":      "https://vault/user",
		"groups_claim":    "/https/~1~1vault~1groups/testing",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cl := sqjwt.Claims{
		Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		Issuer:    "https://team-vault.auth0.com/",
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
	}

	type GroupsLevel2 struct {
		Groups []string `json:"testing"`
	}
	type GroupsLevel1 struct {
		Level2 GroupsLevel2 `json:"//vault/groups"`
	}
	privateCl := struct {
		User   string       `json:"https://vault/user"`
		Level1 GroupsLevel1 `json:"https"`
	}{
		"jeff",
		GroupsLevel1{
			GroupsLevel2{
				[]string{"foo", "bar"},
			},
		},
	}

	jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error: %v", resp.Error())
	}

	auth := resp.Auth
	switch {
	case len(auth.Policies) != 1 || auth.Policies[0] != "test":
		t.Fatal(auth.Policies)
	case auth.Alias.Name != "jeff":
		t.Fatal(auth.Alias.Name)
	case len(auth.GroupAliases) != 2 || auth.GroupAliases[0].Name != "foo" || auth.GroupAliases[1].Name != "bar":
		t.Fatal(auth.GroupAliases)
	case auth.Period != 3*time.Second:
		t.Fatal(auth.Period)
	case auth.TTL != time.Second:
		t.Fatal(auth.TTL)
	case auth.MaxTTL != 5*time.Second:
		t.Fatal(auth.MaxTTL)
	}
}

func TestLogin_OIDC_StringGroupClaim(t *testing.T) {
	cfg := testConfig{
		oidc:          true,
		audience:      true,
		jwks:          false,
		defaultLeeway: -1,
		groupsClaim:   "https://vault/groups/string",
	}
	b, storage := setupBackend(t, cfg)

	jwtData := getTestOIDC(t)

	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response")
	}
	if resp.IsError() {
		t.Fatalf("got error: %v", resp.Error())
	}

	auth := resp.Auth
	switch {
	case len(auth.GroupAliases) != 1 || auth.GroupAliases[0].Name != "just_a_string":
		t.Fatal(auth.GroupAliases)
	}
}

func TestLogin_JWKS_Concurrent(t *testing.T) {
	cfg := testConfig{
		audience:      true,
		jwks:          true,
		defaultLeeway: -1,
	}
	b, storage := setupBackend(t, cfg)

	cl := sqjwt.Claims{
		Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		Issuer:    "https://team-vault.auth0.com/",
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
	}

	type orgs struct {
		Primary string `json:"primary"`
	}

	privateCl := struct {
		User   string   `json:"https://vault/user"`
		Groups []string `json:"https://vault/groups"`
		Org    orgs     `json:"org"`
	}{
		"jeff",
		[]string{"foo", "bar"},
		orgs{"engineering"},
	}

	jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	var g errgroup.Group

	for i := 0; i < 100; i++ {
		g.Go(func() error {
			for i := 0; i < 100; i++ {
				resp, err := b.HandleRequest(context.Background(), req)
				if err != nil {
					return err
				}
				if resp.IsError() {
					return fmt.Errorf("got error: %v", resp.Error())
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
}

const (
	ecdsaPrivKey string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKfldwWLPYsHjRL9EVTsjSbzTtcGRu6icohNfIqcb6A+oAoGCCqGSM49
AwEHoUQDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbSq+7+1q9BFxAkzjgKnlkXk5qx
hzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END EC PRIVATE KEY-----`

	ecdsaPubKey string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbS
q+7+1q9BFxAkzjgKnlkXk5qxhzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END PUBLIC KEY-----`

	badPrivKey string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILTAHJm+clBKYCrRDc74Pt7uF7kH+2x2TdL5cH23FEcsoAoGCCqGSM49
AwEHoUQDQgAE+C3CyjVWdeYtIqgluFJlwZmoonphsQbj9Nfo5wrEutv+3RTFnDQh
vttUajcFAcl4beR+jHFYC00vSO4i5jZ64g==
-----END EC PRIVATE KEY-----`
)
