// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestConfig_JWT_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"oidc_discovery_url":            "",
		"oidc_discovery_ca_pem":         "",
		"oidc_client_id":                "",
		"oidc_response_mode":            "",
		"oidc_response_types":           []string{},
		"override_allowed_server_names": []string{},
		"default_role":                  "",
		"jwt_validation_pubkeys":        []string{testJWTPubKey},
		"jwt_supported_algs":            []string{},
		"jwks_url":                      "",
		"jwks_ca_pem":                   "",
		"bound_issuer":                  "http://vault.example.com/",
		"provider_config":               map[string]interface{}{},
		"namespace_in_state":            false,
		"status":                        "valid",
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

	if diff := deep.Equal(resp.Data, data); diff != nil {
		t.Fatalf("Expected did not equal actual: %v", diff)
	}
}

func TestConfig_JWT_Write(t *testing.T) {
	b, storage := getBackend(t)

	// Create a config with too many token verification schemes
	data := map[string]interface{}{
		"oidc_discovery_url":     "http://fake.example.com",
		"jwt_validation_pubkeys": []string{testJWTPubKey},
		"jwks_url":               "http://fake.anotherexample.com",
		"bound_issuer":           "http://vault.example.com/",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "exactly one of") {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// remove oidc_discovery_url, but this still leaves too many
	delete(data, "oidc_discovery_url")

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "exactly one of") {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// remove jwks_url so the config is now valid
	delete(data, "jwks_url")

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

	pubkey, err := certutil.ParsePublicKeyPEM([]byte(testJWTPubKey))
	if err != nil {
		t.Fatal(err)
	}

	expected := &jwtConfig{
		ParsedJWTPubKeys:           []crypto.PublicKey{pubkey},
		JWTValidationPubKeys:       []string{testJWTPubKey},
		JWTSupportedAlgs:           []string{},
		OIDCResponseTypes:          []string{},
		OverrideAllowedServerNames: []string{},
		BoundIssuer:                "http://vault.example.com/",
		ProviderConfig:             map[string]interface{}{},
		NamespaceInState:           true,
	}

	conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}
}

func TestConfig_JWKS_Update(t *testing.T) {
	b, storage := getBackend(t)

	s := newOIDCProvider(t)
	defer s.server.Close()

	cert, err := s.getTLSCert()
	if err != nil {
		t.Fatal(err)
	}

	data := map[string]interface{}{
		"jwks_url":                      s.server.URL + "/certs",
		"jwks_ca_pem":                   cert,
		"oidc_discovery_url":            "",
		"oidc_discovery_ca_pem":         "",
		"oidc_client_id":                "",
		"oidc_response_mode":            "form_post",
		"oidc_response_types":           []string{},
		"override_allowed_server_names": []string{},
		"default_role":                  "",
		"jwt_validation_pubkeys":        []string{},
		"jwt_supported_algs":            []string{},
		"bound_issuer":                  "",
		"provider_config":               map[string]interface{}{},
		"namespace_in_state":            false,
		"status":                        "valid",
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

	if diff := deep.Equal(resp.Data, data); diff != nil {
		t.Fatalf("Expected did not equal actual: %v", diff)
	}
}

func TestConfig_JWKS_Update_Invalid(t *testing.T) {
	b, storage := getBackend(t)

	s := newOIDCProvider(t)
	defer s.server.Close()

	cert, err := s.getTLSCert()
	if err != nil {
		t.Fatal(err)
	}

	data := map[string]interface{}{
		"jwks_url":               s.server.URL + "/certs_missing",
		"jwks_ca_pem":            cert,
		"oidc_discovery_url":     "",
		"oidc_discovery_ca_pem":  "",
		"oidc_client_id":         "",
		"default_role":           "",
		"jwt_validation_pubkeys": []string{},
		"jwt_supported_algs":     []string{},
		"bound_issuer":           "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if !strings.Contains(resp.Error().Error(), "error checking jwks URL") {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	data["jwks_url"] = s.server.URL + "/certs_invalid"

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if !strings.Contains(resp.Error().Error(), "error checking jwks URL") {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}
}

func TestConfig_ResponseMode(t *testing.T) {
	b, storage := getBackend(t)

	tests := []struct {
		mode        string
		errExpected bool
	}{
		{"", false},
		{"form_post", false},
		{"query", false},
		{"QUERY", true},
		{"abc", true},
	}

	for _, test := range tests {
		data := map[string]interface{}{
			"oidc_response_mode":     test.mode,
			"jwt_validation_pubkeys": []string{testJWTPubKey},
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if test.errExpected {
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Fatalf("expected error, got none for %q", test.mode)
			}
		} else {
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}
		}
	}
}

func TestConfig_OIDC_Write(t *testing.T) {
	b, storage := getBackend(t)

	// First we provide an invalid CA cert to verify that it is in fact paying
	// attention to the value we specify
	data := map[string]interface{}{
		"oidc_discovery_url":    "https://team-vault.auth0.com/",
		"oidc_discovery_ca_pem": oidcBadCACerts,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("expected error")
	}

	delete(data, "oidc_discovery_ca_pem")

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	expected := &jwtConfig{
		JWTValidationPubKeys:       []string{},
		JWTSupportedAlgs:           []string{},
		OIDCResponseTypes:          []string{},
		OverrideAllowedServerNames: []string{},
		OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
		OIDCClientID:               "abc",
		OIDCClientSecret:           "def",
		ProviderConfig:             map[string]interface{}{},
		NamespaceInState:           true,
	}

	conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(expected, conf); diff != nil {
		t.Fatal(diff)
	}

	// Verify OIDC config sanity:
	//   - if providing client id/secret, discovery URL needs to be set
	//   - both oidc client and secret should be provided if either one is
	tests := []struct {
		id   string
		data map[string]interface{}
	}{
		{
			"missing discovery URL",
			map[string]interface{}{
				"jwt_validation_pubkeys": []string{"a"},
				"oidc_client_id":         "abc",
				"oidc_client_secret":     "def",
			},
		},
		{
			"missing secret",
			map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"oidc_client_id":     "abc",
			},
		},
		{
			"missing ID",
			map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"oidc_client_secret": "abc",
			},
		},
	}

	for _, test := range tests {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      test.data,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("test '%s', %v", test.id, err)
		}
		if !resp.IsError() {
			t.Fatalf("test '%s', expected error", test.id)
		}
	}
}

func TestConfig_OIDC_Write_ProviderConfig(t *testing.T) {
	b, storage := getBackend(t)
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	t.Run("valid provider_config", func(t *testing.T) {
		req.Data = map[string]interface{}{
			"oidc_discovery_url": "https://team-vault.auth0.com/",
			"provider_config": map[string]interface{}{
				"provider":     "azure",
				"extraOptions": "abound",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		expected := &jwtConfig{
			JWTValidationPubKeys:       []string{},
			JWTSupportedAlgs:           []string{},
			OIDCResponseTypes:          []string{},
			OverrideAllowedServerNames: []string{},
			OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
			ProviderConfig: map[string]interface{}{
				"provider":     "azure",
				"extraOptions": "abound",
			},
			NamespaceInState: true,
		}

		conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(expected, conf); diff != nil {
			t.Fatal(diff)
		}
	})

	t.Run("unknown provider in provider_config", func(t *testing.T) {
		req.Data = map[string]interface{}{
			"oidc_discovery_url": "https://team-vault.auth0.com/",
			"provider_config": map[string]interface{}{
				"provider": "unknown",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
		assert.EqualError(t, resp.Error(), "invalid provider_config: provider \"unknown\" not found in custom providers")
	})

	t.Run("provider_config missing provider", func(t *testing.T) {
		req.Data = map[string]interface{}{
			"oidc_discovery_url": "https://team-vault.auth0.com/",
			"provider_config": map[string]interface{}{
				"not-provider": "oops",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
		assert.EqualError(t, resp.Error(), "invalid provider_config: 'provider' field not found in provider_config")
	})

	t.Run("provider_config not set", func(t *testing.T) {
		req.Data = map[string]interface{}{
			"oidc_discovery_url": "https://team-vault.auth0.com/",
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		expected := &jwtConfig{
			JWTValidationPubKeys:       []string{},
			JWTSupportedAlgs:           []string{},
			OIDCResponseTypes:          []string{},
			OverrideAllowedServerNames: []string{},
			OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
			ProviderConfig:             map[string]interface{}{},
			NamespaceInState:           true,
		}

		conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(expected, conf); diff != nil {
			t.Fatal(diff)
		}
	})
}

func TestConfig_OIDC_Create_Namespace(t *testing.T) {
	type testCase struct {
		create   map[string]interface{}
		expected jwtConfig
	}
	tests := map[string]testCase{
		"namespace_in_state not specified": {
			create: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           true,
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
		"namespace_in_state true": {
			create: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": true,
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           true,
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
		"namespace_in_state false": {
			create: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": false,
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           false,
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      test.create,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
			assert.NoError(t, err)
			assert.Equal(t, &test.expected, conf)
		})
	}
}

func TestConfig_OIDC_Update_Namespace(t *testing.T) {
	type testCase struct {
		existing map[string]interface{}
		update   map[string]interface{}
		expected jwtConfig
	}
	tests := map[string]testCase{
		"existing false, update to true": {
			existing: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": false,
			},
			update: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": true,
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           true,
				OIDCResponseTypes:          []string{},
				JWTSupportedAlgs:           []string{},
				OverrideAllowedServerNames: []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
		"existing false, update something else": {
			existing: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": false,
			},
			update: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"default_role":       "ui",
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           false,
				DefaultRole:                "ui",
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
		"existing true, update to false": {
			existing: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": true,
			},
			update: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": false,
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           false,
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
		"existing true, update something else": {
			existing: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"namespace_in_state": true,
			},
			update: map[string]interface{}{
				"oidc_discovery_url": "https://team-vault.auth0.com/",
				"default_role":       "ui",
			},
			expected: jwtConfig{
				OIDCDiscoveryURL:           "https://team-vault.auth0.com/",
				NamespaceInState:           true,
				DefaultRole:                "ui",
				OIDCResponseTypes:          []string{},
				OverrideAllowedServerNames: []string{},
				JWTSupportedAlgs:           []string{},
				JWTValidationPubKeys:       []string{},
				ProviderConfig:             map[string]interface{}{},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      test.existing,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			req.Data = test.update
			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
			assert.NoError(t, err)
			assert.Equal(t, &test.expected, conf)
		})
	}
}

// TestConfig_OIDC_Ignore ensures that saving oidc_discovery_url will succeed
// if skip_jwks_validation=true.
func TestConfig_OIDC_Ignore(t *testing.T) {
	b, storage := getBackend(t)
	// Provide an invalid CA cert to verify that it is in fact paying
	// attention to the value we specified, but set skip_jwks_validation=true
	data := map[string]interface{}{
		"oidc_discovery_url":    "https://team-vault.auth0.com/",
		"oidc_discovery_ca_pem": oidcBadCACerts,
		"skip_jwks_validation":  true,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error; expected warning: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error; expected warning: %#v", resp)
	}

	if len(resp.Warnings) == 0 {
		t.Fatalf("expected at least one verification warning: %#v", resp)
	}

	// Reading the config should give the same result.
	req.Operation = logical.ReadOperation
	req.Data = nil

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error; expected warning: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error; expected warning: %#v", resp)
	}

	if len(resp.Warnings) == 0 {
		t.Fatalf("expected at least one verification warning: %#v", resp)
	}
}

// certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com
func TestConfig_CAContext_MismatchedHost(t *testing.T) {
	type testCase struct {
		nameInCertificate     string
		allowedServerNames    []string
		expectedFailureString string
		expectSuccess         bool
		addRootCA             bool
	}
	tests := map[string]testCase{
		"domain not in list": {
			nameInCertificate:     "example.com",
			allowedServerNames:    []string{"invalid.com"},
			addRootCA:             true,
			expectSuccess:         false,
			expectedFailureString: "certificate is valid for example.com, not invalid.com",
		},
		"invalid root CA": {
			nameInCertificate:     "example.com",
			allowedServerNames:    []string{"example.com"},
			addRootCA:             false,
			expectSuccess:         false,
			expectedFailureString: "",
		},
		"domain in list, list size 1": {
			nameInCertificate:     "example.com",
			allowedServerNames:    []string{"example.com"},
			addRootCA:             true,
			expectSuccess:         true,
			expectedFailureString: "",
		},
		"domain in list, list size 3": {
			nameInCertificate:     "example.com",
			allowedServerNames:    []string{"test.com", "example.com", "test2.com"},
			addRootCA:             true,
			expectSuccess:         true,
			expectedFailureString: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, err, caPEM := getCertificate(test.nameInCertificate)
			require.NoError(t, err)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "Hello")
			}))

			server.TLS = config
			server.StartTLS()

			defer server.Close()

			ctx, _ := context.WithCancel(context.Background())
			uri := server.URL

			b := new(jwtAuthBackend)
			req, err := http.NewRequest("GET", uri, nil)
			require.NoError(t, err)

			rootCAString := ""
			if test.addRootCA {
				rootCAString = string(caPEM.Bytes())
			}

			caCtx, err := b.createCAContext(ctx, rootCAString, test.allowedServerNames)
			client, ok := caCtx.Value(oauth2.HTTPClient).(*http.Client)
			if !ok {
				t.Fatalf("unexpected error; can't retrieve client")
			}

			_, err = client.Do(req.WithContext(caCtx))
			if test.expectSuccess == true {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if test.expectedFailureString != "" {
					if !strings.Contains(err.Error(), test.expectedFailureString) {
						t.Fatalf("error is '%s', should contain '%s' but doesnt", err.Error(), test.expectedFailureString)
					}
				}
			}
		})
	}
}

func getCertificate(hostname string) (serverTLSConf *tls.Config, err error, caPEM *bytes.Buffer) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
			CommonName:    hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	caPEM = new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 111)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ServerName:   hostname,
	}

	return
}

const (
	testJWTPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`

	oidcBadCACerts = `-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIJAK8uAVsPxWKGMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTgwNzA5MTgwODI5WhcNMjgwNzA2MTgwODI5WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1eaEmIHKQqDlSadCtg6YY332qIMoeSb2iZTRhBRYBXRhMIKF3HoLXlI8
/3veheMnBQM7zxIeLwtJ4VuZVZcpJlqHdsXQVj6A8+8MlAzNh3+Xnv0tjZ83QLwZ
D6FWvMEzihxATD9uTCu2qRgeKnMYQFq4EG72AGb5094zfsXTAiwCfiRPVumiNbs4
Mr75vf+2DEhqZuyP7GR2n3BKzrWo62yAmgLQQ07zfd1u1buv8R72HCYXYpFul5qx
slZHU3yR+tLiBKOYB+C/VuB7hJZfVx25InIL1HTpIwWvmdk3QzpSpAGIAxWMXSzS
oRmBYGnsgR6WTymfXuokD4ZhHOpFZQIDAQABo1MwUTAdBgNVHQ4EFgQURh/QFJBn
hMXcgB1bWbGiU9B2VBQwHwYDVR0jBBgwFoAURh/QFJBnhMXcgB1bWbGiU9B2VBQw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAr8CZLA3MQjMDWweS
ax9S1fRb8ifxZ4RqDcLj3dw5KZqnjEo8ggczR66T7vVXet/2TFBKYJAM0np26Z4A
WjZfrDT7/bHXseWQAUhw/k2d39o+Um4aXkGpg1Paky9D+ddMdbx1hFkYxDq6kYGd
PlBYSEiYQvVxDx7s7H0Yj9FWKO8WIO6BRUEvLlG7k/Xpp1OI6dV3nqwJ9CbcbqKt
ff4hAtoAmN0/x6yFclFFWX8s7bRGqmnoj39/r98kzeGFb/lPKgQjSVcBJuE7UO4k
8HP6vsnr/ruSlzUMv6XvHtT68kGC1qO3MfqiPhdSa4nxf9g/1xyBmAw/Uf90BJrm
sj9DpQ==
-----END CERTIFICATE-----`
)
