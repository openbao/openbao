// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/oauth2"
)

const (
	responseTypeCode     = "code"      // Authorization code flow
	responseTypeIDToken  = "id_token"  // ID Token for form post
	responseModeQuery    = "query"     // Response as a redirect with query parameters
	responseModeFormPost = "form_post" // Response as an HTML Form
)

func pathConfig(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
		},
		Fields: map[string]*framework.FieldSchema{
			"oidc_discovery_url": {
				Type:        framework.TypeString,
				Description: `OIDC Discovery URL, without any .well-known component (base path). Cannot be used with "jwks_url" or "jwt_validation_pubkeys".`,
			},
			"oidc_discovery_ca_pem": {
				Type:        framework.TypeString,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used.",
			},
			"oidc_client_id": {
				Type:        framework.TypeString,
				Description: "The OAuth Client ID configured with your OIDC provider.",
			},
			"oidc_client_secret": {
				Type:        framework.TypeString,
				Description: "The OAuth Client Secret configured with your OIDC provider.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"oidc_response_mode": {
				Type:        framework.TypeString,
				Description: "The response mode to be used in the OAuth2 request. Allowed values are 'query' and 'form_post'.",
			},
			"oidc_response_types": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The response types to request. Allowed values are 'code' and 'id_token'. Defaults to 'code'.",
			},
			"jwks_url": {
				Type:        framework.TypeString,
				Description: `JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".`,
			},
			"jwks_ca_pem": {
				Type:        framework.TypeString,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.",
			},
			"default_role": {
				Type:        framework.TypeLowerCaseString,
				Description: "The default role to use if none is provided during login. If not set, a role is required during login.",
			},
			"jwt_validation_pubkeys": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with "jwks_url" or "oidc_discovery_url".`,
			},
			"jwt_supported_algs": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A list of supported signing algorithms. Defaults to RS256.`,
			},
			"bound_issuer": {
				Type:        framework.TypeString,
				Description: "The value against which to match the 'iss' claim in a JWT. Optional.",
			},
			"provider_config": {
				Type:        framework.TypeMap,
				Description: "Provider-specific configuration. Optional.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Provider Config",
				},
			},
			"override_allowed_server_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "A list of hostnames to accept when performing TLS validation, which applies both to OIDC and JWKS. This overrides default checks that expect the TLS subject to match the hostname specified in the connection URL",
			},
			"namespace_in_state": {
				Type:        framework.TypeBool,
				Description: "Pass namespace in the OIDC state parameter instead of as a separate query parameter. With this setting, the allowed redirect URL(s) in OpenBao and on the provider side should not contain a namespace query parameter. This means only one redirect URL entry needs to be maintained on the provider side for all OpenBao namespaces that will be authenticating against it. Defaults to true for new configs.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Namespace in OIDC state",
					Value: true,
				},
			},
			"skip_jwks_validation": {
				Type:        framework.TypeBool,
				Description: "When true and oidc_discovery_url or jwks_url are specified, if the connection fails to load, a warning will be issued and status can be checked later by reading the config endpoint.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the current JWT authentication backend configuration.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathConfigWrite,
				Summary:     "Configure the JWT authentication backend.",
				Description: confHelpDesc,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *jwtAuthBackend) config(ctx context.Context, s logical.Storage) (*jwtConfig, error) {
	b.l.Lock()
	defer b.l.Unlock()

	if b.cachedConfig != nil {
		return b.cachedConfig, nil
	}

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &jwtConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	for _, v := range config.JWTValidationPubKeys {
		key, err := certutil.ParsePublicKeyPEM([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("error parsing public key: %w", err)
		}
		config.ParsedJWTPubKeys = append(config.ParsedJWTPubKeys, key)
	}

	b.cachedConfig = config

	return config, nil
}

func contactIssuer(ctx context.Context, uri string, data *url.Values, ignoreBad bool) ([]byte, error) {
	var req *http.Request
	var err error
	if data == nil {
		req, err = http.NewRequest("GET", uri, nil)
	} else {
		req, err = http.NewRequest("POST", uri, strings.NewReader(data.Encode()))
	}
	if err != nil {
		return nil, err
	}
	if data != nil {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		client = http.DefaultClient
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK && (!ignoreBad || resp.StatusCode != http.StatusBadRequest) {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	return body, nil
}

// Discover the device_authorization_endpoint URL and store it in the config
// This should be in coreos/go-oidc but they don't yet support device flow
// At the same time, look up token_endpoint and store it as well
// Returns nil on success, otherwise returns an error
func (b *jwtAuthBackend) configDeviceAuthURL(ctx context.Context, s logical.Storage) error {
	config, err := b.config(ctx, s)
	if err != nil {
		return err
	}

	b.l.Lock()
	defer b.l.Unlock()

	if config.OIDCDeviceAuthURL != "" {
		if config.OIDCDeviceAuthURL == "N/A" {
			return errors.New("no device auth endpoint url discovered")
		}
		return nil
	}

	caCtx, err := b.createCAContext(b.providerCtx, config.OIDCDiscoveryCAPEM, config.OverrideAllowedServerNames)
	if err != nil {
		return fmt.Errorf("error creating context for device auth: %w", err)
	}

	issuer := config.OIDCDiscoveryURL

	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	body, err := contactIssuer(caCtx, wellKnown, nil, false)
	if err != nil {
		return fmt.Errorf("error reading issuer config: %w", err)
	}

	var daj struct {
		DeviceAuthURL string `json:"device_authorization_endpoint"`
		TokenURL      string `json:"token_endpoint"`
	}
	err = json.Unmarshal(body, &daj)
	if err != nil || daj.DeviceAuthURL == "" {
		b.cachedConfig.OIDCDeviceAuthURL = "N/A"
		return errors.New("no device auth endpoint url discovered")
	}

	b.cachedConfig.OIDCDeviceAuthURL = daj.DeviceAuthURL
	b.cachedConfig.OIDCTokenURL = daj.TokenURL
	return nil
}

func (b *jwtAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	if err != nil {
		return nil, err
	}

	// Omit sensitive keys from provider-specific config
	providerConfig := make(map[string]interface{})
	if provider != nil {
		for k, v := range config.ProviderConfig {
			providerConfig[k] = v
		}

		for _, k := range provider.SensitiveKeys() {
			delete(providerConfig, k)
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"oidc_discovery_url":            config.OIDCDiscoveryURL,
			"oidc_discovery_ca_pem":         config.OIDCDiscoveryCAPEM,
			"oidc_client_id":                config.OIDCClientID,
			"oidc_response_mode":            config.OIDCResponseMode,
			"oidc_response_types":           config.OIDCResponseTypes,
			"default_role":                  config.DefaultRole,
			"jwt_validation_pubkeys":        config.JWTValidationPubKeys,
			"jwt_supported_algs":            config.JWTSupportedAlgs,
			"jwks_url":                      config.JWKSURL,
			"jwks_ca_pem":                   config.JWKSCAPEM,
			"bound_issuer":                  config.BoundIssuer,
			"provider_config":               providerConfig,
			"override_allowed_server_names": config.OverrideAllowedServerNames,
			"namespace_in_state":            config.NamespaceInState,
		},
	}

	// Check if the config is currently valid and warn otherwise.
	_, err = b.jwtValidator(config)
	if err != nil {
		resp.AddWarning(fmt.Sprintf("failed to construct JWK validator: %v", err))
		resp.Data["status"] = "invalid"
	} else {
		resp.Data["status"] = "valid"
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &jwtConfig{
		OIDCDiscoveryURL:           d.Get("oidc_discovery_url").(string),
		OIDCDiscoveryCAPEM:         d.Get("oidc_discovery_ca_pem").(string),
		OIDCClientID:               d.Get("oidc_client_id").(string),
		OIDCClientSecret:           d.Get("oidc_client_secret").(string),
		OIDCResponseMode:           d.Get("oidc_response_mode").(string),
		OIDCResponseTypes:          d.Get("oidc_response_types").([]string),
		JWKSURL:                    d.Get("jwks_url").(string),
		JWKSCAPEM:                  d.Get("jwks_ca_pem").(string),
		DefaultRole:                d.Get("default_role").(string),
		JWTValidationPubKeys:       d.Get("jwt_validation_pubkeys").([]string),
		JWTSupportedAlgs:           d.Get("jwt_supported_algs").([]string),
		BoundIssuer:                d.Get("bound_issuer").(string),
		ProviderConfig:             d.Get("provider_config").(map[string]interface{}),
		OverrideAllowedServerNames: d.Get("override_allowed_server_names").([]string),
	}

	skipJwksValidation := d.Get("skip_jwks_validation").(bool)

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	// Check if the config already exists, to determine if this is a create or
	// an update, since req.Operation is always 'update' in this handler, and
	// there's no existence check defined.
	existingConfig, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if nsInState, ok := d.GetOk("namespace_in_state"); ok {
		config.NamespaceInState = nsInState.(bool)
	} else if existingConfig == nil {
		// new configs default to true
		config.NamespaceInState = true
	} else {
		// maintain the existing value
		config.NamespaceInState = existingConfig.NamespaceInState
	}

	// Run checks on values
	methodCount := 0
	if config.OIDCDiscoveryURL != "" {
		methodCount++
	}
	if len(config.JWTValidationPubKeys) != 0 {
		methodCount++
	}
	if config.JWKSURL != "" {
		methodCount++
	}

	resp := &logical.Response{}
	switch {
	case methodCount != 1:
		return logical.ErrorResponse("exactly one of 'jwt_validation_pubkeys', 'jwks_url' or 'oidc_discovery_url' must be set"), nil

	case config.OIDCClientID != "" && config.OIDCClientSecret == "",
		config.OIDCClientID == "" && config.OIDCClientSecret != "":
		return logical.ErrorResponse("both 'oidc_client_id' and 'oidc_client_secret' must be set for OIDC"), nil

	case config.OIDCDiscoveryURL != "":
		var err error
		if config.OIDCClientID != "" && config.OIDCClientSecret != "" {
			_, err = b.createProvider(config)
		} else {
			_, err = jwt.NewOIDCDiscoveryKeySet(ctx, config.OIDCDiscoveryURL, config.OIDCDiscoveryCAPEM)
		}
		if err != nil {
			if !skipJwksValidation {
				b.Logger().Error("error checking oidc discovery URL", "error", err)
				return logical.ErrorResponse("error checking oidc discovery URL"), nil
			}

			resp.AddWarning("error checking oidc discovery URL")
		}

	case config.OIDCClientID != "" && config.OIDCDiscoveryURL == "":
		return logical.ErrorResponse("'oidc_discovery_url' must be set for OIDC"), nil

	case config.JWKSURL != "":
		keyset, err := jwt.NewJSONWebKeySet(ctx, config.JWKSURL, config.JWKSCAPEM)
		if err != nil {
			b.Logger().Error("error checking jwks_ca_pem", "error", err)
			return logical.ErrorResponse("error checking jwks_ca_pem"), nil
		}

		// Try to verify a correctly formatted JWT. The signature will fail to match, but other
		// errors with fetching the remote keyset should be reported.
		testJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
		_, err = keyset.VerifySignature(ctx, testJWT)
		if err == nil {
			err = errors.New("unexpected verification of JWT")
		}

		if !strings.Contains(err.Error(), "failed to verify id token signature") {
			if !skipJwksValidation {
				b.Logger().Error("error checking jwks URL", "error", err)
				return logical.ErrorResponse("error checking jwks URL"), nil
			}

			resp.AddWarning("error checking jwks URL")
		}

	case len(config.JWTValidationPubKeys) != 0:
		for _, v := range config.JWTValidationPubKeys {
			if _, err := certutil.ParsePublicKeyPEM([]byte(v)); err != nil {
				return logical.ErrorResponse(fmt.Errorf("error parsing public key: %w", err).Error()), nil
			}
		}

	default:
		return nil, errors.New("unknown condition")
	}

	// NOTE: the OIDC lib states that if nothing is passed into its config, it
	// defaults to "RS256". So in the case of a zero value here it won't
	// default to e.g. "none".
	if err := jwt.SupportedSigningAlgorithm(toAlg(config.JWTSupportedAlgs)...); err != nil {
		return logical.ErrorResponse("invalid jwt_supported_algs: %s", err), nil
	}

	// Validate response_types
	if !strutil.StrListSubset([]string{responseTypeCode, responseTypeIDToken}, config.OIDCResponseTypes) {
		return logical.ErrorResponse("invalid response_types %v. 'code' and 'id_token' are allowed", config.OIDCResponseTypes), nil
	}

	// Validate response_mode
	switch config.OIDCResponseMode {
	case "", responseModeQuery:
		if config.hasType(responseTypeIDToken) {
			return logical.ErrorResponse("query response_mode may not be used with an id_token response_type"), nil
		}
	case responseModeFormPost:
	default:
		return logical.ErrorResponse("invalid response_mode: %q", config.OIDCResponseMode), nil
	}

	// Validate provider_config
	if _, err := NewProviderConfig(ctx, config, ProviderMap()); err != nil {
		return logical.ErrorResponse("invalid provider_config: %s", err), nil
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if len(resp.Warnings) > 0 {
		return resp, nil
	}

	return nil, nil
}

func (b *jwtAuthBackend) createProvider(config *jwtConfig) (*oidc.Provider, error) {
	supportedSigAlgs := make([]oidc.Alg, len(config.JWTSupportedAlgs))
	for i, a := range config.JWTSupportedAlgs {
		supportedSigAlgs[i] = oidc.Alg(a)
	}

	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []oidc.Alg{oidc.RS256}
	}

	c, err := oidc.NewConfig(config.OIDCDiscoveryURL, config.OIDCClientID,
		oidc.ClientSecret(config.OIDCClientSecret), supportedSigAlgs, []string{},
		oidc.WithProviderCA(config.OIDCDiscoveryCAPEM))
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	provider, err := oidc.NewProvider(c)
	if err != nil {
		return nil, fmt.Errorf("error creating provider with given values: %w", err)
	}

	return provider, nil
}

// createCAContext returns a context with custom TLS client, configured with the root certificates
// from caPEM. If no certificates are configured, the original context is returned.
func (b *jwtAuthBackend) createCAContext(ctx context.Context, caPEM string, allowedServerNames []string) (context.Context, error) {
	tlsConfig := &tls.Config{}

	err := b.OverrideRootCAs(tlsConfig, caPEM)
	if err != nil {
		return nil, err
	}

	err = b.OverrideAllowedServerNames(tlsConfig, allowedServerNames)
	if err != nil {
		return nil, err
	}

	tr := cleanhttp.DefaultPooledTransport()
	tr.TLSClientConfig = tlsConfig

	tc := &http.Client{
		Transport: tr,
	}

	caCtx := context.WithValue(ctx, oauth2.HTTPClient, tc)

	return caCtx, nil
}

func (b *jwtAuthBackend) OverrideRootCAs(config *tls.Config, caPEM string) error {
	if caPEM != "" {
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(caPEM)); !ok {
			return errors.New("could not parse CA PEM value successfully")
		}

		config.RootCAs = certPool
	}

	return nil
}

// allowedServerNames contain a list of hostnames for which we will accept a *valid* certificate for.
func (b *jwtAuthBackend) OverrideAllowedServerNames(config *tls.Config, allowedServerNames []string) error {
	if len(allowedServerNames) > 0 {
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(cs tls.ConnectionState) error {
			var err error
			var successfulValidation bool

			for _, allowedServerName := range allowedServerNames {
				opts := x509.VerifyOptions{
					DNSName:       allowedServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         config.RootCAs,
				}

				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}

				chains, verifyErr := cs.PeerCertificates[0].Verify(opts)
				if verifyErr != nil {
					err = verifyErr
					continue
				}

				_, fipsErr := fipsAllowedChains(chains)
				if fipsErr != nil {
					err = fipsErr
					continue
				}

				successfulValidation = true
				break
			}

			if !successfulValidation {
				return err
			} else {
				return nil
			}
		}
	}

	return nil
}

type jwtConfig struct {
	OIDCDiscoveryURL           string                 `json:"oidc_discovery_url"`
	OIDCDiscoveryCAPEM         string                 `json:"oidc_discovery_ca_pem"`
	OIDCClientID               string                 `json:"oidc_client_id"`
	OIDCClientSecret           string                 `json:"oidc_client_secret"`
	OIDCResponseMode           string                 `json:"oidc_response_mode"`
	OIDCResponseTypes          []string               `json:"oidc_response_types"`
	JWKSURL                    string                 `json:"jwks_url"`
	JWKSCAPEM                  string                 `json:"jwks_ca_pem"`
	JWTValidationPubKeys       []string               `json:"jwt_validation_pubkeys"`
	JWTSupportedAlgs           []string               `json:"jwt_supported_algs"`
	BoundIssuer                string                 `json:"bound_issuer"`
	DefaultRole                string                 `json:"default_role"`
	ProviderConfig             map[string]interface{} `json:"provider_config"`
	OverrideAllowedServerNames []string               `json:"override_allowed_server_names"`
	NamespaceInState           bool                   `json:"namespace_in_state"`

	ParsedJWTPubKeys []crypto.PublicKey `json:"-"`
	// These are looked up from OIDCDiscoveryURL when needed
	OIDCDeviceAuthURL string `json:"-"`
	OIDCTokenURL      string `json:"-"`
}

const (
	StaticKeys = iota
	JWKS
	OIDCDiscovery
	OIDCFlow
	unconfigured
)

// authType classifies the authorization type/flow based on config parameters.
func (c jwtConfig) authType() int {
	switch {
	case len(c.ParsedJWTPubKeys) > 0:
		return StaticKeys
	case c.JWKSURL != "":
		return JWKS
	case c.OIDCDiscoveryURL != "":
		if c.OIDCClientID != "" && c.OIDCClientSecret != "" {
			return OIDCFlow
		}
		return OIDCDiscovery
	}

	return unconfigured
}

// hasType returns whether the list of response types includes the requested
// type. The default type is 'code' so that special case is handled as well.
func (c jwtConfig) hasType(t string) bool {
	if len(c.OIDCResponseTypes) == 0 && t == responseTypeCode {
		return true
	}

	return slices.Contains(c.OIDCResponseTypes, t)
}

// Adapted from similar code in https://github.com/golang/go/blob/86fca3dcb63157b8e45e565e821e7fb098fcf368/src/crypto/tls/handshake_client.go#L1160-L1181
func fipsAllowedChains(chains [][]*x509.Certificate) ([][]*x509.Certificate, error) {
	if !fips140.Enabled() {
		return chains, nil
	}

	permittedChains := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		if fipsAllowChain(chain) {
			permittedChains = append(permittedChains, chain)
		}
	}

	if len(permittedChains) == 0 {
		return nil, errors.New("tls: no FIPS compatible certificate chains found")
	}

	return permittedChains, nil
}

func fipsAllowChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

	for _, cert := range chain {
		if !isCertificateAllowedFIPS(cert) {
			return false
		}
	}

	return true
}

func isCertificateAllowedFIPS(c *x509.Certificate) bool {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return true
	default:
		return false
	}
}

const (
	confHelpSyn = `
Configures the JWT authentication backend.
`
	confHelpDesc = `
The JWT authentication backend validates JWTs (or OIDC) using the configured
credentials. If using OIDC Discovery, the URL must be provided, along
with (optionally) the CA cert to use for the connection. If performing JWT
validation locally, a set of public keys must be provided.
`
)
