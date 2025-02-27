// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/identitytpl"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/ed25519"
)

type oidcConfig struct {
	Issuer string `json:"issuer"`

	// effectiveIssuer is a calculated field and will be either Issuer (if
	// that's set) or the Vault instance's api_addr.
	effectiveIssuer string
}

type expireableKey struct {
	KeyID    string    `json:"key_id"`
	ExpireAt time.Time `json:"expire_at"`
}

type namedKey struct {
	name             string
	Algorithm        string           `json:"signing_algorithm"`
	VerificationTTL  time.Duration    `json:"verification_ttl"`
	RotationPeriod   time.Duration    `json:"rotation_period"`
	KeyRing          []*expireableKey `json:"key_ring"`
	SigningKey       *jose.JSONWebKey `json:"signing_key"`
	NextSigningKey   *jose.JSONWebKey `json:"next_signing_key"`
	NextRotation     time.Time        `json:"next_rotation"`
	AllowedClientIDs []string         `json:"allowed_client_ids"`
}

type role struct {
	TokenTTL time.Duration `json:"token_ttl"`
	Key      string        `json:"key"`
	Template string        `json:"template"`
	ClientID string        `json:"client_id"`
}

// idToken contains the required OIDC fields.
//
// Templated claims will be merged into the final output. Those claims may
// include top-level keys, but those keys may not overwrite any of the
// required OIDC fields.
type idToken struct {
	Issuer          string `json:"iss"`       // api_addr or custom Issuer
	Namespace       string `json:"namespace"` // Namespace of issuer
	Subject         string `json:"sub"`       // Entity ID
	Audience        string `json:"aud"`       // Role or client ID will be used here.
	Expiry          int64  `json:"exp"`       // Expiration, as determined by the role or client.
	IssuedAt        int64  `json:"iat"`       // Time of token creation
	Nonce           string `json:"nonce"`     // Nonce given in OIDC authentication requests
	AuthTime        int64  `json:"auth_time"` // AuthTime given in OIDC authentication requests
	AccessTokenHash string `json:"at_hash"`   // Access token hash value
	CodeHash        string `json:"c_hash"`    // Authorization code hash value
}

// discovery contains a subset of the required elements of OIDC discovery needed
// for JWT verification libraries to use the .well-known endpoint.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type discovery struct {
	Issuer        string   `json:"issuer"`
	Keys          string   `json:"jwks_uri"`
	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
}

// oidcCache is a thin wrapper around go-cache to partition by namespace
type oidcCache struct {
	c *cache.Cache
}

var errNilNamespace = errors.New("nil namespace in oidc cache request")

const (
	issuerPath           = "identity/oidc"
	oidcTokensPrefix     = "oidc_tokens/"
	namedKeyCachePrefix  = "namedKeys/"
	oidcConfigStorageKey = oidcTokensPrefix + "config/"
	namedKeyConfigPath   = oidcTokensPrefix + "named_keys/"
	publicKeysConfigPath = oidcTokensPrefix + "public_keys/"
	roleConfigPath       = oidcTokensPrefix + "roles/"

	// Error constants used in the Introspect Endpoint. See details at
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
	ErrIntrospectInvalidClient = "invalid_client"
)

var (
	reservedClaims = []string{
		"iat", "aud", "exp", "iss",
		"sub", "namespace", "nonce",
		"auth_time", "at_hash", "c_hash",
	}
	supportedAlgs = []string{
		string(jose.RS256),
		string(jose.RS384),
		string(jose.RS512),
		string(jose.ES256),
		string(jose.ES384),
		string(jose.ES512),
		string(jose.EdDSA),
	}
)

// pseudo-namespace for cache items that don't belong to any real namespace.
var noNamespace = &namespace.Namespace{ID: "__NO_NAMESPACE"}

type ClientAuthenticationError struct {
	StatusCode string
	Err        error
}

func (e *ClientAuthenticationError) Error() string {
	return fmt.Sprintf("status-code %s: %v", e.StatusCode, e.Err)
}

func NewClientAuthenticationError(statusCode string, err error) *ClientAuthenticationError {
	return &ClientAuthenticationError{
		StatusCode: statusCode,
		Err:        err,
	}
}

func (i *IdentityStore) authenticateWithClientCredentials(ctx context.Context, req *logical.Request, d *framework.FieldData) (*client, *provider, *ClientAuthenticationError) {
	// Used header: "Authorization: Basic [client_id:client_secret]"
	// Potentially used fields: "client_id", "client_secret", "name" (provider-name)

	// Require the OIDC provider, if specified in the schema.
	providerName, isProviderDefinedInSchema := d.GetOk("name")
	var provider *provider = nil
	if isProviderDefinedInSchema {
		p, err := i.getOIDCProvider(ctx, req.Storage, providerName.(string))
		if err != nil {
			return nil, nil, NewClientAuthenticationError("server_error", err)
		}
		if p == nil {
			return nil, nil, NewClientAuthenticationError("invalid_request", errors.New("provider not found"))
		}
		provider = p
	}

	// Check for client credentials in the Authorization header
	clientID, clientSecret, okBasicAuth := basicAuth(req)
	if !okBasicAuth {
		// Check for client credentials in the request body
		clientID = d.Get("client_id").(string)
		clientSecret = d.Get("client_secret").(string)
		if clientID == "" {
			return nil, nil, NewClientAuthenticationError("invalid_request", errors.New("client_id parameter is required"))
		}
	}

	client, err := i.clientByID(ctx, req.Storage, clientID)
	if err != nil {
		return nil, nil, NewClientAuthenticationError("server_error", err)
	}
	if client == nil {
		i.Logger().Debug("client failed to authenticate with client not found", "client_id", clientID)
		return nil, nil, NewClientAuthenticationError("invalid_client", errors.New("client failed to authenticate"))
	}

	// Authenticate the client if it's a confidential client type.
	// Details at https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
	if client.Type == confidential &&
		subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) == 0 {
		i.Logger().Debug("client failed to authenticate with invalid client secret", "client_id", clientID)
		return nil, nil, NewClientAuthenticationError("invalid_client", errors.New("client failed to authenticate"))
	}

	// Validate that the client is authorized to use the provider (if any).
	// Note that 'provider' can only be nil here, if it was explicitly allowed
	// to be nil - it does not mean there was a lookup failure, that would have
	// resulted in a 'provider not found' response earlier.
	if provider != nil && !provider.allowedClientID(clientID) {
		return nil, nil, NewClientAuthenticationError("invalid_client", errors.New("client is not authorized to use the provider"))
	}

	return client, provider, nil
}

func oidcPaths(i *IdentityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "oidc/config/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
			},

			Fields: map[string]*framework.FieldSchema{
				"issuer": {
					Type:        framework.TypeString,
					Description: "Issuer URL to be used in the iss claim of the token. If not set, OpenBao's app_addr will be used.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCReadConfig,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "configuration",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCUpdateConfig,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
			},

			HelpSynopsis:    "OIDC configuration",
			HelpDescription: "Update OIDC configuration in the identity backend",
		},
		{
			Pattern: "oidc/key/" + framework.GenericNameRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "key",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
				},

				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "How often to generate a new keypair.",
					Default:     "24h",
				},

				"verification_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Controls how long the public portion of a key will be available for verification after being rotated.",
					Default:     "24h",
				},

				"algorithm": {
					Type:        framework.TypeString,
					Description: "Signing algorithm to use. This will default to RS256.",
					Default:     "RS256",
				},

				"allowed_client_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma separated string or array of role client ids allowed to use this key for signing. If empty no roles are allowed. If \"*\" all roles are allowed.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: i.pathOIDCCreateUpdateKey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCCreateUpdateKey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCReadKey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.pathOIDCDeleteKey,
				},
			},
			ExistenceCheck:  i.pathOIDCKeyExistenceCheck,
			HelpSynopsis:    "CRUD operations for OIDC keys.",
			HelpDescription: "Create, Read, Update, and Delete OIDC named keys.",
		},
		{
			Pattern: "oidc/key/" + framework.GenericNameRegex("name") + "/rotate/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationVerb:   "rotate",
				OperationSuffix: "key",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
				},
				"verification_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Controls how long the public portion of a key will be available for verification after being rotated. Setting verification_ttl here will override the verification_ttl set on the key.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCRotateKey,
				},
			},
			HelpSynopsis:    "Rotate a named OIDC key.",
			HelpDescription: "Manually rotate a named OIDC key. Rotating a named key will cause a new underlying signing key to be generated. The public portion of the underlying rotated signing key will continue to live for the verification_ttl duration.",
		},
		{
			Pattern: "oidc/key/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "keys",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.pathOIDCListKey,
				},
			},
			HelpSynopsis:    "List OIDC keys",
			HelpDescription: "List all named OIDC keys",
		},
		{
			Pattern: "oidc/\\.well-known/openid-configuration/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "open-id-configuration",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCDiscovery,
				},
			},
			HelpSynopsis:    "Query OIDC configurations",
			HelpDescription: "Query this path to retrieve the configured OIDC Issuer and Keys endpoints, response types, subject types, and signing algorithms used by the OIDC backend.",
		},
		{
			Pattern: "oidc/\\.well-known/keys/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "public-keys",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCReadPublicKeys,
				},
			},
			HelpSynopsis:    "Retrieve public keys",
			HelpDescription: "Query this path to retrieve the public portion of keys used to sign OIDC tokens. Clients can use this to validate the authenticity of the OIDC token claims.",
		},
		{
			Pattern: "oidc/token/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationVerb:   "generate",
				OperationSuffix: "token",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCGenerateToken,
				},
			},
			HelpSynopsis:    "Generate an OIDC token",
			HelpDescription: "Generate an OIDC token against a configured role. The OpenBao token used to call this path must have a corresponding entity.",
		},
		{
			Pattern: "oidc/role/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				"key": {
					Type:        framework.TypeString,
					Description: "The OIDC key to use for generating tokens. The specified key must already exist.",
					Required:    true,
				},
				"template": {
					Type:        framework.TypeString,
					Description: "The template string to use for generating tokens. This may be in string-ified JSON or base64 format.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "TTL of the tokens generated against the role.",
					Default:     "24h",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "Optional client_id",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCCreateUpdateRole,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: i.pathOIDCCreateUpdateRole,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.pathOIDCReadRole,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.pathOIDCDeleteRole,
				},
			},
			ExistenceCheck:  i.pathOIDCRoleExistenceCheck,
			HelpSynopsis:    "CRUD operations on OIDC Roles",
			HelpDescription: "Create, Read, Update, and Delete OIDC Roles. OIDC tokens are generated against roles which can be configured to determine how OIDC tokens are generated.",
		},
		{
			Pattern: "oidc/role/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.pathOIDCListRole,
				},
			},
			HelpSynopsis:    "List configured OIDC roles",
			HelpDescription: "List all configured OIDC roles in the identity backend.",
		},
		{
			Pattern: "oidc/introspect/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationVerb:   "introspect",
			},
			Fields: map[string]*framework.FieldSchema{
				"token": {
					Type:        framework.TypeString,
					Description: "ID-Token to verify",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "Optional client_id to verify",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCIntrospect,
				},
			},
			HelpSynopsis:    "Verify the authenticity of an OIDC token",
			HelpDescription: "Use this path to verify the authenticity of an OIDC token and whether the associated entity is active and enabled.",
		},
		{
			Pattern: "oidc/introspect-access-token/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "oidc",
				OperationVerb:   "introspect-access-token",
			},
			Fields: map[string]*framework.FieldSchema{
				"token": {
					Type:        framework.TypeString,
					Description: "Access-Token to verify",
					Required:    true,
				},
				"token_type_hint": {
					Type:        framework.TypeString,
					Description: "The token type. Only 'access_token' is expected.",
				},
				// For confidential clients, the client_id and client_secret are provided to
				// the token endpoint via the 'client_secret_basic' or 'client_secret_post'
				// authentication methods. See the OIDC spec for details at:
				// https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
				"client_id": {
					Type:        framework.TypeString,
					Description: "The ID of the requesting client.",
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "The secret of the requesting client.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.pathOIDCIntrospectAccessToken,
				},
			},
			HelpSynopsis:    "Provides the OIDC Introspect Endpoint, intended to validate access-tokens using OIDC client-credentials.",
			HelpDescription: "The OIDC Introspect Endpoint allows an OpenBao-Client to lookup the validity, audience and expiration of an Access Token.",
		},
	}
}

func (i *IdentityStore) pathOIDCReadConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := i.getOIDCConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"issuer": c.Issuer,
		},
	}

	if i.redirectAddr == "" && c.Issuer == "" {
		resp.AddWarning(`Both "issuer" and OpenBao's "api_addr" are empty. ` +
			`The issuer claim in generated tokens will not be network reachable.`)
	}

	return resp, nil
}

func (i *IdentityStore) pathOIDCUpdateConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp *logical.Response

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	issuerRaw, ok := d.GetOk("issuer")
	if !ok {
		return nil, nil
	}

	issuer := issuerRaw.(string)

	if issuer != "" {
		// verify that issuer is the correct format:
		//   - http or https
		//   - host name
		//   - optional port
		//   - nothing more
		valid := false
		if u, err := url.Parse(issuer); err == nil {
			u2 := url.URL{
				Scheme: u.Scheme,
				Host:   u.Host,
			}
			valid = (*u == u2) &&
				(u.Scheme == "http" || u.Scheme == "https") &&
				u.Host != ""
		}

		if !valid {
			return logical.ErrorResponse(
				"invalid issuer, which must include only a scheme, host, " +
					"and optional port (e.g. https://example.com:8200)"), nil
		}

		resp = &logical.Response{
			Warnings: []string{`If "issuer" is set explicitly, all tokens must be ` +
				`validated against that address, including those issued by secondary ` +
				`clusters. Setting issuer to "" will restore the default behavior of ` +
				`using the cluster's api_addr as the issuer.`},
		}
	}

	c := oidcConfig{
		Issuer: issuer,
	}

	entry, err := logical.StorageEntryJSON(oidcConfigStorageKey, c)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	return resp, nil
}

func (i *IdentityStore) getOIDCConfig(ctx context.Context, s logical.Storage) (*oidcConfig, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	v, ok, err := i.oidcCache.Get(ns, "config")
	if err != nil {
		return nil, err
	}

	if ok {
		return v.(*oidcConfig), nil
	}

	var c oidcConfig
	entry, err := s.Get(ctx, oidcConfigStorageKey)
	if err != nil {
		return nil, err
	}

	if entry != nil {
		if err := entry.DecodeJSON(&c); err != nil {
			return nil, err
		}
	}

	c.effectiveIssuer = c.Issuer
	if c.effectiveIssuer == "" {
		c.effectiveIssuer = i.redirectAddr
	}

	c.effectiveIssuer += "/v1/" + ns.Path + issuerPath

	if err := i.oidcCache.SetDefault(ns, "config", &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// pathOIDCCreateUpdateKey is used to create a new named key or update an existing one
func (i *IdentityStore) pathOIDCCreateUpdateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)

	i.oidcLock.Lock()
	defer i.oidcLock.Unlock()

	var key namedKey
	if req.Operation == logical.UpdateOperation {
		entry, err := req.Storage.Get(ctx, namedKeyConfigPath+name)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&key); err != nil {
				return nil, err
			}
		}
	}

	if rotationPeriodRaw, ok := d.GetOk("rotation_period"); ok {
		key.RotationPeriod = time.Duration(rotationPeriodRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		key.RotationPeriod = time.Duration(d.Get("rotation_period").(int)) * time.Second
	}

	if key.RotationPeriod < 1*time.Minute {
		return logical.ErrorResponse("rotation_period must be at least one minute"), nil
	}

	if verificationTTLRaw, ok := d.GetOk("verification_ttl"); ok {
		key.VerificationTTL = time.Duration(verificationTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		key.VerificationTTL = time.Duration(d.Get("verification_ttl").(int)) * time.Second
	}

	if key.VerificationTTL > 10*key.RotationPeriod {
		return logical.ErrorResponse("verification_ttl cannot be longer than 10x rotation_period"), nil
	}

	if req.Operation == logical.UpdateOperation {
		// ensure any roles referencing this key do not already have a token_ttl
		// greater than the key's verification_ttl
		roles, err := i.rolesReferencingTargetKeyName(ctx, req, name)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if role.TokenTTL > key.VerificationTTL {
				errorMessage := fmt.Sprintf(
					"unable to update key %q because it is currently referenced by one or more roles with a token ttl greater than %d seconds",
					name,
					key.VerificationTTL/time.Second,
				)
				return logical.ErrorResponse(errorMessage), nil
			}
		}

		// ensure any clients referencing this key do not already have a id_token_ttl
		// greater than the key's verification_ttl
		clients, err := i.clientsReferencingTargetKeyName(ctx, req, name)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			if client.IDTokenTTL > key.VerificationTTL {
				errorMessage := fmt.Sprintf(
					"unable to update key %q because it is currently referenced by one or more clients with an id_token_ttl greater than %d seconds",
					name,
					key.VerificationTTL/time.Second,
				)
				return logical.ErrorResponse(errorMessage), nil
			}
		}
	}

	if allowedClientIDsRaw, ok := d.GetOk("allowed_client_ids"); ok {
		key.AllowedClientIDs = allowedClientIDsRaw.([]string)
	} else if req.Operation == logical.CreateOperation {
		key.AllowedClientIDs = d.Get("allowed_client_ids").([]string)
	}

	prevAlgorithm := key.Algorithm
	if algorithm, ok := d.GetOk("algorithm"); ok {
		key.Algorithm = algorithm.(string)
	} else if req.Operation == logical.CreateOperation {
		key.Algorithm = d.Get("algorithm").(string)
	}

	if !strutil.StrListContains(supportedAlgs, key.Algorithm) {
		return logical.ErrorResponse("unknown signing algorithm %q", key.Algorithm), nil
	}

	now := time.Now()

	// Update next rotation time if it is unset or now earlier than previously set.
	nextRotation := now.Add(key.RotationPeriod)
	if key.NextRotation.IsZero() || nextRotation.Before(key.NextRotation) {
		key.NextRotation = nextRotation
	}

	// generate current and next keys if creating a new key or changing algorithms
	if key.Algorithm != prevAlgorithm {
		err = key.generateAndSetKey(ctx, i.Logger(), req.Storage)
		if err != nil {
			return nil, err
		}

		err = key.generateAndSetNextKey(ctx, i.Logger(), req.Storage)
		if err != nil {
			return nil, err
		}
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	// store named key
	entry, err := logical.StorageEntryJSON(namedKeyConfigPath+name, key)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// handleOIDCReadKey is used to read an existing key
func (i *IdentityStore) pathOIDCReadKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	i.oidcLock.RLock()
	defer i.oidcLock.RUnlock()

	entry, err := req.Storage.Get(ctx, namedKeyConfigPath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var storedNamedKey namedKey
	if err := entry.DecodeJSON(&storedNamedKey); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"rotation_period":    int64(storedNamedKey.RotationPeriod.Seconds()),
			"verification_ttl":   int64(storedNamedKey.VerificationTTL.Seconds()),
			"algorithm":          storedNamedKey.Algorithm,
			"allowed_client_ids": storedNamedKey.AllowedClientIDs,
		},
	}, nil
}

// keyIDsByName will return a slice of key IDs for the given key name
func (i *IdentityStore) keyIDsByName(ctx context.Context, s logical.Storage, name string) ([]string, error) {
	var keyIDs []string
	entry, err := s.Get(ctx, namedKeyConfigPath+name)
	if err != nil {
		return keyIDs, err
	}
	if entry == nil {
		return keyIDs, nil
	}

	var key namedKey
	if err := entry.DecodeJSON(&key); err != nil {
		return keyIDs, err
	}

	for _, k := range key.KeyRing {
		keyIDs = append(keyIDs, k.KeyID)
	}

	return keyIDs, nil
}

// rolesReferencingTargetKeyName returns a map of role names to roles
// referencing targetKeyName.
//
// Note: this is not threadsafe. It is to be called with Lock already held.
func (i *IdentityStore) rolesReferencingTargetKeyName(ctx context.Context, req *logical.Request, targetKeyName string) (map[string]role, error) {
	roleNames, err := req.Storage.List(ctx, roleConfigPath)
	if err != nil {
		return nil, err
	}

	var tempRole role
	roles := make(map[string]role)
	for _, roleName := range roleNames {
		entry, err := req.Storage.Get(ctx, roleConfigPath+roleName)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&tempRole); err != nil {
				return nil, err
			}
			if tempRole.Key == targetKeyName {
				roles[roleName] = tempRole
			}
		}
	}

	return roles, nil
}

// roleNamesReferencingTargetKeyName returns a slice of strings of role
// names referencing targetKeyName.
//
// Note: this is not threadsafe. It is to be called with Lock already held.
func (i *IdentityStore) roleNamesReferencingTargetKeyName(ctx context.Context, req *logical.Request, targetKeyName string) ([]string, error) {
	roles, err := i.rolesReferencingTargetKeyName(ctx, req, targetKeyName)
	if err != nil {
		return nil, err
	}

	var names []string
	for key := range roles {
		names = append(names, key)
	}
	sort.Strings(names)
	return names, nil
}

// handleOIDCDeleteKey is used to delete a key
func (i *IdentityStore) pathOIDCDeleteKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	targetKeyName := d.Get("name").(string)

	if targetKeyName == defaultKeyName {
		return logical.ErrorResponse("deletion of key %q not allowed",
			defaultKeyName), nil
	}

	i.oidcLock.Lock()

	roleNames, err := i.roleNamesReferencingTargetKeyName(ctx, req, targetKeyName)
	if err != nil {
		i.oidcLock.Unlock()
		return nil, err
	}

	if len(roleNames) > 0 {
		errorMessage := fmt.Sprintf("unable to delete key %q because it is currently referenced by these roles: %s",
			targetKeyName, strings.Join(roleNames, ", "))
		i.oidcLock.Unlock()
		return logical.ErrorResponse(errorMessage), logical.ErrInvalidRequest
	}

	clientNames, err := i.clientNamesReferencingTargetKeyName(ctx, req, targetKeyName)
	if err != nil {
		i.oidcLock.Unlock()
		return nil, err
	}

	if len(clientNames) > 0 {
		errorMessage := fmt.Sprintf("unable to delete key %q because it is currently referenced by these clients: %s",
			targetKeyName, strings.Join(clientNames, ", "))
		i.oidcLock.Unlock()
		return logical.ErrorResponse(errorMessage), logical.ErrInvalidRequest
	}

	// key can safely be deleted now
	err = req.Storage.Delete(ctx, namedKeyConfigPath+targetKeyName)
	if err != nil {
		i.oidcLock.Unlock()
		return nil, err
	}

	i.oidcLock.Unlock()

	_, err = i.expireOIDCPublicKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	return nil, nil
}

// handleOIDCListKey is used to list named keys
func (i *IdentityStore) pathOIDCListKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	i.oidcLock.RLock()
	defer i.oidcLock.RUnlock()

	keys, err := req.Storage.List(ctx, namedKeyConfigPath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

// pathOIDCRotateKey is used to manually trigger a rotation on the named key
func (i *IdentityStore) pathOIDCRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)

	i.oidcLock.Lock()
	defer i.oidcLock.Unlock()

	// load the named key and perform a rotation
	entry, err := req.Storage.Get(ctx, namedKeyConfigPath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("no named key found at %q", name), logical.ErrInvalidRequest
	}

	var storedNamedKey namedKey
	if err := entry.DecodeJSON(&storedNamedKey); err != nil {
		return nil, err
	}
	storedNamedKey.name = name

	// call rotate with an appropriate overrideTTL where < 0 means no override
	verificationTTLOverride := -1 * time.Second

	if ttlRaw, ok := d.GetOk("verification_ttl"); ok {
		verificationTTLOverride = time.Duration(ttlRaw.(int)) * time.Second
	}

	if err := storedNamedKey.rotate(ctx, i.Logger(), req.Storage, verificationTTLOverride); err != nil {
		return nil, err
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	return nil, nil
}

func (i *IdentityStore) pathOIDCKeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	i.oidcLock.RLock()
	defer i.oidcLock.RUnlock()

	entry, err := req.Storage.Get(ctx, namedKeyConfigPath+name)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

// handleOIDCGenerateSignToken generates and signs an OIDC token
func (i *IdentityStore) pathOIDCGenerateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	roleName := d.Get("name").(string)

	role, err := i.getOIDCRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	key, err := i.getNamedKey(ctx, req.Storage, role.Key)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key %q not found", role.Key), nil
	}

	// Validate that the role is allowed to sign with its key (the key could have been updated)
	if !strutil.StrListContains(key.AllowedClientIDs, "*") && !strutil.StrListContains(key.AllowedClientIDs, role.ClientID) {
		return logical.ErrorResponse("the key %q does not list the client ID of the role %q as an allowed client ID", role.Key, roleName), nil
	}

	// generate an OIDC token from entity data
	if req.EntityID == "" {
		return logical.ErrorResponse("no entity associated with the request's token"), nil
	}

	config, err := i.getOIDCConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	retResp := &logical.Response{}
	expiry := role.TokenTTL
	if expiry > key.VerificationTTL {
		expiry = key.VerificationTTL
		retResp.AddWarning(fmt.Sprintf("a role's token ttl cannot be longer "+
			"than the verification_ttl of the key it references, setting token ttl to %d", expiry))
	}

	now := time.Now()
	idToken := idToken{
		Issuer:    config.effectiveIssuer,
		Namespace: ns.ID,
		Subject:   req.EntityID,
		Audience:  role.ClientID,
		Expiry:    now.Add(expiry).Unix(),
		IssuedAt:  now.Unix(),
	}

	e, err := i.MemDBEntityByID(req.EntityID, true)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("error loading entity ID %q", req.EntityID)
	}

	groups, inheritedGroups, err := i.groupsByEntityID(e.ID)
	if err != nil {
		return nil, err
	}

	groups = append(groups, inheritedGroups...)

	// Parse and integrate the populated template. Structural errors with the template _should_
	// be caught during configuration. Error found during runtime will be logged, but they will
	// not block generation of the basic ID token. They should not be returned to the requester.
	_, populatedTemplate, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
		Mode:        identitytpl.JSONTemplating,
		String:      role.Template,
		Entity:      identity.ToSDKEntity(e),
		Groups:      identity.ToSDKGroups(groups),
		NamespaceID: ns.ID,
	})
	if err != nil {
		i.Logger().Warn("error populating OIDC token template", "template", role.Template, "error", err)
	}

	payload, err := idToken.generatePayload(i.Logger(), populatedTemplate)
	if err != nil {
		i.Logger().Warn("error populating OIDC token template", "error", err)
	}

	signedIdToken, err := key.signPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("error signing OIDC token: %w", err)
	}

	retResp.Data = map[string]interface{}{
		"token":     signedIdToken,
		"client_id": role.ClientID,
		"ttl":       int64(role.TokenTTL.Seconds()),
	}
	return retResp, nil
}

func (i *IdentityStore) getNamedKey(ctx context.Context, s logical.Storage, name string) (*namedKey, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Attempt to get the key from the cache
	keyRaw, found, err := i.oidcCache.Get(ns, namedKeyCachePrefix+name)
	if err != nil {
		return nil, err
	}
	if key, ok := keyRaw.(*namedKey); ok && found {
		return key, nil
	}

	// Fall back to reading the key from storage
	entry, err := s.Get(ctx, namedKeyConfigPath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var key namedKey
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}

	// Cache the key
	if err := i.oidcCache.SetDefault(ns, namedKeyCachePrefix+name, &key); err != nil {
		i.logger.Warn("failed to cache key", "error", err)
	}

	return &key, nil
}

func (tok *idToken) generatePayload(logger hclog.Logger, templates ...string) ([]byte, error) {
	output := map[string]interface{}{
		"iss":       tok.Issuer,
		"namespace": tok.Namespace,
		"sub":       tok.Subject,
		"aud":       tok.Audience,
		"exp":       tok.Expiry,
		"iat":       tok.IssuedAt,
	}

	// Copy optional claims into output
	if len(tok.Nonce) > 0 {
		output["nonce"] = tok.Nonce
	}
	if tok.AuthTime > 0 {
		output["auth_time"] = tok.AuthTime
	}
	if len(tok.AccessTokenHash) > 0 {
		output["at_hash"] = tok.AccessTokenHash
	}
	if len(tok.CodeHash) > 0 {
		output["c_hash"] = tok.CodeHash
	}

	// Merge each of the populated JSON templates into output
	err := mergeJSONTemplates(logger, output, templates...)
	if err != nil {
		logger.Error("failed to populate templates for ID token generation", "error", err)
		return nil, err
	}

	payload, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// mergeJSONTemplates will merge each of the given JSON templates into the given
// output map. It will simply merge the top-level keys of the unmarshalled JSON
// templates into output, which means that any conflicting keys will be overwritten.
func mergeJSONTemplates(logger hclog.Logger, output map[string]interface{}, templates ...string) error {
	for _, template := range templates {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(template), &parsed); err != nil {
			logger.Warn("error parsing OIDC template", "template", template, "err", err)
		}

		for k, v := range parsed {
			if !strutil.StrListContains(reservedClaims, k) {
				output[k] = v
			} else {
				logger.Warn("invalid top level OIDC template key", "template", template, "key", k)
			}
		}
	}

	return nil
}

// generateAndSetKey will generate new signing and public key pairs and set
// them as the SigningKey.
func (k *namedKey) generateAndSetKey(ctx context.Context, logger hclog.Logger, s logical.Storage) error {
	signingKey, err := generateKeys(k.Algorithm)
	if err != nil {
		return err
	}

	k.SigningKey = signingKey
	k.KeyRing = append(k.KeyRing, &expireableKey{KeyID: signingKey.Public().KeyID})

	if err := saveOIDCPublicKey(ctx, s, signingKey.Public()); err != nil {
		return err
	}
	logger.Debug("generated OIDC public key to sign JWTs", "key_id", signingKey.Public().KeyID)
	return nil
}

// generateAndSetNextKey will generate new signing and public key pairs and set
// them as the NextSigningKey.
func (k *namedKey) generateAndSetNextKey(ctx context.Context, logger hclog.Logger, s logical.Storage) error {
	signingKey, err := generateKeys(k.Algorithm)
	if err != nil {
		return err
	}

	k.NextSigningKey = signingKey
	k.KeyRing = append(k.KeyRing, &expireableKey{KeyID: signingKey.Public().KeyID})

	if err := saveOIDCPublicKey(ctx, s, signingKey.Public()); err != nil {
		return err
	}
	logger.Debug("generated OIDC public key for future use", "key_id", signingKey.Public().KeyID)
	return nil
}

func (k *namedKey) signPayload(payload []byte) (string, error) {
	if k.SigningKey == nil {
		return "", errors.New("signing key is nil; rotate the key and try again")
	}
	signingKey := jose.SigningKey{Key: k.SigningKey, Algorithm: jose.SignatureAlgorithm(k.Algorithm)}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	signedIdToken, err := signature.CompactSerialize()
	if err != nil {
		return "", err
	}

	return signedIdToken, nil
}

func (i *IdentityStore) pathOIDCRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := i.getOIDCRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathOIDCCreateUpdateRole is used to create a new role or update an existing one
func (i *IdentityStore) pathOIDCCreateUpdateRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)

	i.oidcLock.Lock()
	defer i.oidcLock.Unlock()

	var role role
	if req.Operation == logical.UpdateOperation {
		entry, err := req.Storage.Get(ctx, roleConfigPath+name)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&role); err != nil {
				return nil, err
			}
		}
	}

	if key, ok := d.GetOk("key"); ok {
		role.Key = key.(string)
	} else if req.Operation == logical.CreateOperation {
		role.Key = d.Get("key").(string)
	}

	if role.Key == "" {
		return logical.ErrorResponse("the key parameter is required"), nil
	}

	if role.Key == defaultKeyName {
		if err := i.lazyGenerateDefaultKey(ctx, req.Storage); err != nil {
			return nil, fmt.Errorf("failed to generate default key: %w", err)
		}
	}

	if template, ok := d.GetOk("template"); ok {
		role.Template = template.(string)
	} else if req.Operation == logical.CreateOperation {
		role.Template = d.Get("template").(string)
	}

	// Attempt to decode as base64 and use that if it works
	if decoded, err := base64.StdEncoding.DecodeString(role.Template); err == nil {
		role.Template = string(decoded)
	}

	// Validate that template can be parsed and results in valid JSON
	if role.Template != "" {
		_, populatedTemplate, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
			Mode:   identitytpl.JSONTemplating,
			String: role.Template,
			Entity: new(logical.Entity),
			Groups: make([]*logical.Group, 0),
			// namespace?
		})
		if err != nil {
			return logical.ErrorResponse("error parsing template: %s", err.Error()), nil
		}

		var tmp map[string]interface{}
		if err := json.Unmarshal([]byte(populatedTemplate), &tmp); err != nil {
			return logical.ErrorResponse("error parsing template JSON: %s", err.Error()), nil
		}

		for key := range tmp {
			if strutil.StrListContains(reservedClaims, key) {
				return logical.ErrorResponse(`top level key %q not allowed. Restricted keys: %s`,
					key, strings.Join(reservedClaims, ", ")), nil
			}
		}
	}

	if ttl, ok := d.GetOk("ttl"); ok {
		role.TokenTTL = time.Duration(ttl.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.TokenTTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	// get the key referenced by this role if it exists
	var key namedKey
	entry, err := req.Storage.Get(ctx, namedKeyConfigPath+role.Key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("cannot find key %q", role.Key), nil
	}

	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}
	if role.TokenTTL > key.VerificationTTL {
		return logical.ErrorResponse("a role's token ttl cannot be longer than the verification_ttl of the key it references"), nil
	}

	if clientID, ok := d.GetOk("client_id"); ok {
		role.ClientID = clientID.(string)
	}

	// create role path
	if role.ClientID == "" {
		clientID, err := base62.Random(26)
		if err != nil {
			return nil, err
		}
		role.ClientID = clientID
	}

	// store role (which was either just created or updated)
	entry, err = logical.StorageEntryJSON(roleConfigPath+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	return nil, nil
}

// handleOIDCReadRole is used to read an existing role
func (i *IdentityStore) pathOIDCReadRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := i.getOIDCRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"client_id": role.ClientID,
			"key":       role.Key,
			"template":  role.Template,
			"ttl":       int64(role.TokenTTL.Seconds()),
		},
	}, nil
}

func (i *IdentityStore) getOIDCRole(ctx context.Context, s logical.Storage, roleName string) (*role, error) {
	entry, err := s.Get(ctx, roleConfigPath+roleName)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role role
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

// handleOIDCDeleteRole is used to delete a role if it exists
func (i *IdentityStore) pathOIDCDeleteRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)
	err = req.Storage.Delete(ctx, roleConfigPath+name)
	if err != nil {
		return nil, err
	}

	if err := i.oidcCache.Flush(ns); err != nil {
		return nil, err
	}

	return nil, nil
}

// handleOIDCListRole is used to list stored a roles
func (i *IdentityStore) pathOIDCListRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleConfigPath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (i *IdentityStore) pathOIDCDiscovery(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var data []byte

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	v, ok, err := i.oidcCache.Get(ns, "discoveryResponse")
	if err != nil {
		return nil, err
	}

	if ok {
		data = v.([]byte)
	} else {
		c, err := i.getOIDCConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		disc := discovery{
			Issuer:        c.effectiveIssuer,
			Keys:          c.effectiveIssuer + "/.well-known/keys",
			ResponseTypes: []string{"id_token"},
			Subjects:      []string{"public"},
			IDTokenAlgs:   supportedAlgs,
		}

		data, err = json.Marshal(disc)
		if err != nil {
			return nil, err
		}

		if err := i.oidcCache.SetDefault(ns, "discoveryResponse", data); err != nil {
			return nil, err
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPStatusCode:         200,
			logical.HTTPRawBody:            data,
			logical.HTTPContentType:        "application/json",
			logical.HTTPCacheControlHeader: "max-age=3600",
		},
	}

	return resp, nil
}

// getKeysCacheControlHeader returns the cache control header for all public
// keys at the .well-known/keys endpoint
func (i *IdentityStore) getKeysCacheControlHeader() (string, error) {
	// if jwksCacheControlMaxAge is set use that, otherwise fall back on the
	// more conservative nextRun values
	jwksCacheControlMaxAge, ok, err := i.oidcCache.Get(noNamespace, "jwksCacheControlMaxAge")
	if err != nil {
		return "", err
	}

	if ok {
		maxDuration := int64(jwksCacheControlMaxAge.(time.Duration))
		randDuration := mathrand.Int63n(maxDuration)
		durationInSeconds := time.Duration(randDuration).Seconds()
		return fmt.Sprintf("max-age=%.0f", durationInSeconds), nil
	}

	nextRun, ok, err := i.oidcCache.Get(noNamespace, "nextRun")
	if err != nil {
		return "", err
	}

	if ok {
		now := time.Now()
		expireAt := nextRun.(time.Time)
		if expireAt.After(now) {
			i.Logger().Debug("use nextRun value for Cache Control header", "nextRun", nextRun)
			expireInSeconds := expireAt.Sub(time.Now()).Seconds()
			return fmt.Sprintf("max-age=%.0f", expireInSeconds), nil
		}
	}
	return "", nil
}

// pathOIDCReadPublicKeys is used to retrieve all public keys so that clients can
// verify the validity of a signed OIDC token.
func (i *IdentityStore) pathOIDCReadPublicKeys(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var data []byte

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	v, ok, err := i.oidcCache.Get(ns, "jwksResponse")
	if err != nil {
		return nil, err
	}

	if ok {
		data = v.([]byte)
	} else {
		jwks, err := i.lookupPublicJwksByRoles(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		data, err = json.Marshal(jwks)
		if err != nil {
			return nil, err
		}

		if err := i.oidcCache.SetDefault(ns, "jwksResponse", data); err != nil {
			return nil, err
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPStatusCode:  200,
			logical.HTTPRawBody:     data,
			logical.HTTPContentType: "application/json",
		},
	}

	// set a Cache-Control header only if there are keys
	keys, err := listOIDCPublicKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		header, err := i.getKeysCacheControlHeader()
		if err != nil {
			return nil, err
		}

		if header != "" {
			resp.Data[logical.HTTPCacheControlHeader] = header
		}
	}

	return resp, nil
}

func (i *IdentityStore) pathOIDCIntrospect(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var claims jwt.Claims

	// helper for preparing the non-standard introspection response
	introspectionResp := func(errorMsg string) (*logical.Response, error) {
		response := map[string]interface{}{
			"active": true,
		}

		if errorMsg != "" {
			response["active"] = false
			response["error"] = errorMsg
		}

		data, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				logical.HTTPStatusCode:  200,
				logical.HTTPRawBody:     data,
				logical.HTTPContentType: "application/json",
			},
		}

		return resp, nil
	}

	rawIDToken := d.Get("token").(string)
	clientID := d.Get("client_id").(string)

	// validate basic JWT structure
	parsedJWT, err := jwt.ParseSigned(rawIDToken)
	if err != nil {
		return introspectionResp(fmt.Sprintf("error parsing token: %s", err.Error()))
	}

	// validate JWT signature
	var jwks *jose.JSONWebKeySet
	if clientID == "" {
		jwks, err = i.lookupPublicJwksByRoles(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
	} else {
		jwks, err = i.lookupPublicJwksByClient(ctx, req.Storage, clientID)
		if err != nil {
			if err.Error() == "invalid client-id" {
				// don't propagate as an *error* to the call-site.
				return introspectionResp(err.Error())
			}
			return nil, err
		}
	}

	// check whether any of the found signing-keys has signed the claims
	var foundValidKey bool
	for _, key := range jwks.Keys {
		if err := parsedJWT.Claims(key, &claims); err == nil {
			foundValidKey = true
			break
		}
	}
	if !foundValidKey {
		return introspectionResp("unable to validate the token signature")
	}

	// validate contents of the claims
	expected := jwt.Expected{
		Time: time.Now(),
	}
	if clientID != "" {
		expected.Audience = []string{clientID}
	}

	_, err = i.getValidClaimsIssuer(ctx, req, claims, expected)
	if err != nil {
		return introspectionResp(fmt.Sprintf("error validating claims: %s", err.Error()))
	}

	// validate entity exists and is active
	entity, err := i.MemDBEntityByID(claims.Subject, true)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return introspectionResp("entity was not found")
	} else if entity.Disabled {
		return introspectionResp("entity is disabled")
	}

	return introspectionResp("")
}

func (i *IdentityStore) getValidClaimsIssuer(ctx context.Context, req *logical.Request, claims jwt.Claims, expected jwt.Expected) (*provider, error) {
	// There is this asymmetry where identity/oidc/provider/{name}/token generates a key,
	// with the provider-name baked into the key-issuer. When validating claims, we asserted
	// that the key-issuer matches the *global* default oidc-conf providers issuer, instead of
	// considering the provider that generated the token as the issuer. This leads to
	// claim-validation failing on the 'iss' claim. Hence, we fetch all providers and see
	// whether one matches the issuer of the token.
	providerNames, err := req.Storage.List(ctx, "oidc_provider/provider/")
	if err != nil {
		return nil, err
	}

	// ensure the 'default' case of 'no provider' is tested *last* (we use the last error-message)
	providerNames = append(providerNames, "")

	var lastClaimsError error

	// iterate over all issuers (providers and oidc-default) and find which can validate the claim.
	for _, providerName := range providerNames {
		var provider *provider
		if providerName == "" {
			// global default, which would not support more than 1 provider
			c, err := i.getOIDCConfig(ctx, req.Storage)
			if err != nil {
				return nil, err
			}
			// validate whether token was issued by the default issuer
			expected.Issuer = c.effectiveIssuer
		} else {
			provider, err = i.getOIDCProvider(ctx, req.Storage, providerName)
			if err != nil {
				return nil, err
			}
			// validate whether token was issued by this provider's issuer
			expected.Issuer = provider.effectiveIssuer
		}

		if claimsErr := claims.Validate(expected); claimsErr != nil {
			lastClaimsError = claimsErr
		} else {
			return provider, nil // provider MAY be nil, meaning: the default oidc-config
		}
	}

	return nil, lastClaimsError
}

func (i *IdentityStore) pathOIDCIntrospectAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Serves the endpoint /v1/identity/oidc/introspect-access-token, which introspects (opaque) access-tokens.
	// N.B.: distinct from /v1/identity/oidc/introspect, which introspects JWT ID-tokens only.
	// Given the completely different approaches, it may take significant effort to merge them into one endpoint.

	// Get the namespace
	ns, err := namespace.FromContext(ctx)
	if ns == nil || err != nil {
		return introspectResponse(nil, ErrIntrospectInvalidClient, "missing namespace")
	}

	authClient, _, authErr := i.authenticateWithClientCredentials(ctx, req, d)
	if err != nil {
		return introspectResponse(nil, authErr.StatusCode, authErr.Error())
	}
	if authClient == nil {
		return introspectResponse(nil, ErrIntrospectInvalidClient, "client failed to authenticate")
	}
	if authClient.Type != confidential {
		// The client that authenticates MUST be confidential.
		// The client that generated the access-token, MAY be confidential.
		return introspectResponse(nil, ErrIntrospectInvalidClient, "client failed to authenticate")
	}

	// Look up the access token
	accessToken := d.Get("token").(string)
	// Currently unused: tokenTypeHint := d.Get("token_type_hint").(string)
	tokenEntry, err := i.tokenStorer.LookupToken(ctx, accessToken)
	if err != nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("token lookup failed")
	}
	if tokenEntry == nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("non-existing or expired token")
	}
	if tokenEntry.Type != logical.TokenTypeBatch {
		return i.convertIntrospectErrorToInactiveTokenResponse("token must be of type 'batch'")
	}

	// Get the client ID that originated the request from the access token metadata
	accessTokenClientID, okClientID := tokenEntry.InternalMeta[accessTokenClientIDMeta]
	if !okClientID {
		return i.convertIntrospectErrorToInactiveTokenResponse("missing client ID in token metadata")
	}

	accessTokenClient, err := i.clientByID(ctx, req.Storage, accessTokenClientID)
	if err != nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("client lookup failed")
	}
	if accessTokenClient == nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("client of token not found")
	}

	accessTokenIat, err := tokenEntry.SentinelGet("creation_time_unix")
	if err != nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("token issued-at calculation failed")
	}

	accessTokenExp, err := tokenEntry.SentinelGet("expiration_time_unix")
	if err != nil {
		return i.convertIntrospectErrorToInactiveTokenResponse("token expiration calculation failed")
	}

	// Construct the response body
	responseBody := map[string]interface{}{
		"active": true,
		"aud":    accessTokenClientID,
	}
	if accessTokenIat != nil {
		responseBody["iat"] = accessTokenIat.(time.Time).Unix()
	}
	if accessTokenExp != nil {
		responseBody["exp"] = accessTokenExp.(time.Time).Unix()
	}
	return introspectResponse(responseBody, "", "")
}

func (i *IdentityStore) convertIntrospectErrorToInactiveTokenResponse(errorDescription string) (*logical.Response, error) {
	// The oidc-introspection specification states that we should be opaque about the reason
	// the provided token could not be validated, and that we just reply with 'active=false'.
	// Details at https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
	i.Logger().Debug("oidc introspect-access-token endpoint failed to validate token", "error_description", errorDescription)

	return introspectResponse(map[string]interface{}{"active": false}, "", "")
}

func introspectResponse(response map[string]interface{}, errorCode, errorDescription string) (*logical.Response, error) {
	statusCode := http.StatusOK

	// Set the error response and status code if error code isn't empty
	if errorCode != "" {
		switch errorCode {
		case ErrIntrospectInvalidClient:
			statusCode = http.StatusUnauthorized
		}

		response = map[string]interface{}{
			"error":             errorCode,
			"error_description": errorDescription,
		}
	}

	body, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		logical.HTTPStatusCode:  statusCode,
		logical.HTTPRawBody:     body,
		logical.HTTPContentType: "application/json",

		// Token responses must include the following HTTP response headers
		// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
		logical.HTTPCacheControlHeader: "no-store",
		logical.HTTPPragmaHeader:       "no-cache",
	}

	// Set the WWW-Authenticate response header when returning the
	// invalid_client error code per the OAuth 2.0 spec at
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if errorCode == ErrIntrospectInvalidClient {
		data[logical.HTTPWWWAuthenticateHeader] = "Basic"
	}

	return &logical.Response{
		Data: data,
	}, nil
}

// namedKey.rotate(overrides) performs a key rotation on a namedKey.
// verification_ttl can be overridden with an overrideVerificationTTL value >= 0
func (k *namedKey) rotate(ctx context.Context, logger hclog.Logger, s logical.Storage, overrideVerificationTTL time.Duration) error {
	verificationTTL := k.VerificationTTL
	if overrideVerificationTTL >= 0 {
		verificationTTL = overrideVerificationTTL
	}

	now := time.Now()
	if k.SigningKey != nil {
		// set the previous public key's expiry time
		for _, key := range k.KeyRing {
			if key.KeyID == k.SigningKey.KeyID {
				key.ExpireAt = now.Add(verificationTTL)
				break
			}
		}
	} else {
		// this can occur for keys generated before vault 1.9.0 but rotated on
		// vault 1.9.0
		logger.Debug("nil signing key detected on rotation")
	}

	if k.NextSigningKey == nil {
		logger.Debug("nil next signing key detected on rotation")
		// keys will not have a NextSigningKey if they were generated before
		// vault 1.9
		err := k.generateAndSetNextKey(ctx, logger, s)
		if err != nil {
			return err
		}
	}

	// do the rotation
	k.SigningKey = k.NextSigningKey
	k.NextRotation = now.Add(k.RotationPeriod)

	// now that we have rotated, generate a new NextSigningKey
	err := k.generateAndSetNextKey(ctx, logger, s)
	if err != nil {
		return err
	}

	// store named key (it was modified when rotate was called on it)
	entry, err := logical.StorageEntryJSON(namedKeyConfigPath+k.name, k)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	logger.Debug("rotated OIDC public key, now using", "key_id", k.SigningKey.Public().KeyID)
	return nil
}

// generateKeys returns a signingKey and publicKey pair
func generateKeys(algorithm string) (*jose.JSONWebKey, error) {
	var key interface{}
	var err error

	switch algorithm {
	case "RS256", "RS384", "RS512":
		// 2048 bits is recommended by RSA Laboratories as a minimum post 2015
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return nil, err
		}
	case "ES256", "ES384", "ES512":
		var curve elliptic.Curve

		switch algorithm {
		case "ES256":
			curve = elliptic.P256()
		case "ES384":
			curve = elliptic.P384()
		case "ES512":
			curve = elliptic.P521()
		}

		if key, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
			return nil, err
		}
	case "EdDSA":
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown algorithm %q", algorithm)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	jwk := &jose.JSONWebKey{
		Key:       key,
		KeyID:     id,
		Algorithm: algorithm,
		Use:       "sig",
	}

	return jwk, nil
}

func saveOIDCPublicKey(ctx context.Context, s logical.Storage, key jose.JSONWebKey) error {
	entry, err := logical.StorageEntryJSON(publicKeysConfigPath+key.KeyID, key)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func loadOIDCPublicKey(ctx context.Context, s logical.Storage, keyID string) (*jose.JSONWebKey, error) {
	entry, err := s.Get(ctx, publicKeysConfigPath+keyID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("could not find key with ID %s", keyID)
	}

	var key jose.JSONWebKey
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}

	return &key, nil
}

func listOIDCPublicKeys(ctx context.Context, s logical.Storage) ([]string, error) {
	keys, err := s.List(ctx, publicKeysConfigPath)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (i *IdentityStore) lookupPublicJwksByRoles(ctx context.Context, s logical.Storage) (*jose.JSONWebKeySet, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	jwksRaw, ok, err := i.oidcCache.Get(ns, "jwks")
	if err != nil {
		return nil, err
	}

	if ok {
		return jwksRaw.(*jose.JSONWebKeySet), nil
	}

	if _, err := i.expireOIDCPublicKeys(ctx, s); err != nil {
		return nil, err
	}

	// only return keys that are associated with a role
	roleNames, err := s.List(ctx, roleConfigPath)
	if err != nil {
		return nil, err
	}

	// collect and deduplicate the key IDs for all roles
	keyIDs := make(map[string]struct{})
	for _, roleName := range roleNames {
		role, err := i.getOIDCRole(ctx, s, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}

		roleKeyIDs, err := i.keyIDsByName(ctx, s, role.Key)
		if err != nil {
			return nil, err
		}

		for _, keyID := range roleKeyIDs {
			keyIDs[keyID] = struct{}{}
		}
	}

	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0, len(keyIDs)),
	}

	// load the JSON web key for each key ID
	for keyID := range keyIDs {
		key, err := loadOIDCPublicKey(ctx, s, keyID)
		if err != nil {
			return nil, err
		}
		jwks.Keys = append(jwks.Keys, *key)
	}

	if err := i.oidcCache.SetDefault(ns, "jwks", jwks); err != nil {
		return nil, err
	}

	return jwks, nil
}

func (i *IdentityStore) lookupPublicJwksByClient(ctx context.Context, s logical.Storage, clientID string) (*jose.JSONWebKeySet, error) {
	client, err := i.clientByID(ctx, s, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("invalid client-id")
	}

	clientKey, err := i.getNamedKey(ctx, s, client.Key)
	if err != nil {
		return nil, err
	}
	if clientKey == nil {
		return nil, errors.New("missing client-named-key")
	}
	if clientKey.SigningKey == nil {
		return nil, errors.New("missing client-signing-key")
	}

	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0, 1),
	}
	jwks.Keys = append(jwks.Keys, clientKey.SigningKey.Public())

	return jwks, nil
}

func (i *IdentityStore) expireOIDCPublicKeys(ctx context.Context, s logical.Storage) (time.Time, error) {
	var didUpdate bool

	i.oidcLock.Lock()
	defer i.oidcLock.Unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return time.Time{}, err
	}

	// nextExpiration will be the soonest expiration time of all keys. Initialize
	// here to a relatively distant time.
	nextExpiration := time.Now().Add(24 * time.Hour)
	now := time.Now()

	publicKeyIDs, err := listOIDCPublicKeys(ctx, s)
	if err != nil {
		return now, err
	}

	keyNames, err := s.List(ctx, namedKeyConfigPath)
	if err != nil {
		return now, err
	}

	usedKeys := make([]string, 0)

	for _, keyName := range keyNames {
		entry, err := s.Get(ctx, namedKeyConfigPath+keyName)
		if err != nil {
			return now, err
		}

		if entry == nil {
			i.Logger().Warn("could not find key to update", "key", keyName)
			continue
		}

		var key namedKey
		if err := entry.DecodeJSON(&key); err != nil {
			return now, err
		}

		// Remove any expired keys from the keyring.
		keyRing := key.KeyRing
		var keyringUpdated bool

		for j := 0; j < len(keyRing); j++ {
			k := keyRing[j]
			if !k.ExpireAt.IsZero() && k.ExpireAt.Before(now) {
				keyRing[j] = keyRing[len(keyRing)-1]
				keyRing = keyRing[:len(keyRing)-1]

				keyringUpdated = true
				j--
				continue
			}

			// Save a remaining key's next expiration if it is the earliest we've
			// seen (for use by the periodicFunc for scheduling).
			if !k.ExpireAt.IsZero() && k.ExpireAt.Before(nextExpiration) {
				nextExpiration = k.ExpireAt
			}

			// Mark the KeyId as in use so it doesn't get deleted in the next step
			usedKeys = append(usedKeys, k.KeyID)
		}

		// Persist any keyring updates if necessary
		if keyringUpdated {
			key.KeyRing = keyRing
			entry, err := logical.StorageEntryJSON(entry.Key, key)
			if err != nil {
				i.Logger().Error("error creating storage entry", "key", key.name, "error", err)
				continue
			}

			if err := s.Put(ctx, entry); err != nil {
				i.Logger().Error("error writing key", "key", key.name, "error", err)
				continue
			}
			didUpdate = true
		}
	}

	// Delete all public keys that were not determined to be not expired and in
	// use by some role.
	for _, keyID := range publicKeyIDs {
		if !strutil.StrListContains(usedKeys, keyID) {
			if err := s.Delete(ctx, publicKeysConfigPath+keyID); err != nil {
				i.Logger().Error("error deleting OIDC public key", "key_id", keyID, "error", err)
				nextExpiration = now
				continue
			}
			didUpdate = true
			i.Logger().Debug("deleted OIDC public key", "key_id", keyID)
		}
	}

	if didUpdate {
		if err := i.oidcCache.Flush(ns); err != nil {
			i.Logger().Error("error flushing oidc cache", "error", err)
		}
	}

	return nextExpiration, nil
}

// oidcKeyRotation will rotate any keys that are due to be rotated.
//
// It will return the time of the soonest rotation and the minimum
// verificationTTL or minimum rotationPeriod out of all the current keys.
func (i *IdentityStore) oidcKeyRotation(ctx context.Context, s logical.Storage) (time.Time, time.Duration, error) {
	// soonestRotation will be the soonest rotation time of all keys. Initialize
	// here to a relatively distant time.
	now := time.Now()
	soonestRotation := now.Add(24 * time.Hour)

	jwksClientCacheDuration := time.Duration(math.MaxInt64)

	i.oidcLock.Lock()
	defer i.oidcLock.Unlock()

	keys, err := s.List(ctx, namedKeyConfigPath)
	if err != nil {
		return now, jwksClientCacheDuration, err
	}

	for _, k := range keys {
		entry, err := s.Get(ctx, namedKeyConfigPath+k)
		if err != nil {
			return now, jwksClientCacheDuration, err
		}

		if entry == nil {
			continue
		}

		var key namedKey
		if err := entry.DecodeJSON(&key); err != nil {
			return now, jwksClientCacheDuration, err
		}
		key.name = k

		if key.VerificationTTL < jwksClientCacheDuration {
			jwksClientCacheDuration = key.VerificationTTL
		}

		if key.RotationPeriod < jwksClientCacheDuration {
			jwksClientCacheDuration = key.RotationPeriod
		}

		// Future key rotation that is the earliest we've seen.
		if now.Before(key.NextRotation) && key.NextRotation.Before(soonestRotation) {
			soonestRotation = key.NextRotation
		}

		// Key that is due to be rotated.
		if now.After(key.NextRotation) {
			i.Logger().Debug("rotating OIDC key", "key", key.name)
			if err := key.rotate(ctx, i.Logger(), s, -1); err != nil {
				return now, jwksClientCacheDuration, err
			}

			// Possibly save the new rotation time
			if key.NextRotation.Before(soonestRotation) {
				soonestRotation = key.NextRotation
			}
		}
	}

	return soonestRotation, jwksClientCacheDuration, nil
}

// oidcPeriodFunc is invoked by the backend's periodFunc and runs regular key
// rotations and expiration actions.
func (i *IdentityStore) oidcPeriodicFunc(ctx context.Context) {
	var nextRun time.Time
	now := time.Now()

	v, ok, err := i.oidcCache.Get(noNamespace, "nextRun")
	if err != nil {
		i.Logger().Error("error reading oidc cache", "err", err)
		return
	}

	if ok {
		nextRun = v.(time.Time)
	}

	// The condition here is for performance, not precise timing. The actions can
	// be run at any time safely, but there is no need to invoke them (which
	// might be somewhat expensive if there are many roles/keys) if we're not
	// past any rotation/expiration TTLs.
	if now.After(nextRun) {
		// Initialize to a fairly distant next run time. This will be brought in
		// based on key rotation times.
		nextRun = now.Add(24 * time.Hour)
		minJwksClientCacheDuration := time.Duration(math.MaxInt64)

		for _, ns := range i.namespacer.ListNamespaces(true) {
			nsPath := ns.Path

			s := i.router.MatchingStorageByAPIPath(ctx, nsPath+"identity/oidc")

			if s == nil {
				continue
			}

			nextRotation, jwksClientCacheDuration, err := i.oidcKeyRotation(ctx, s)
			if err != nil {
				i.Logger().Warn("error rotating OIDC keys", "err", err)
			}

			nextExpiration, err := i.expireOIDCPublicKeys(ctx, s)
			if err != nil {
				i.Logger().Warn("error expiring OIDC public keys", "err", err)
			}

			if err := i.oidcCache.Flush(ns); err != nil {
				i.Logger().Error("error flushing oidc cache", "err", err)
			}

			// re-run at the soonest expiration or rotation time
			if nextRotation.Before(nextRun) {
				nextRun = nextRotation
			}

			if nextExpiration.Before(nextRun) {
				nextRun = nextExpiration
			}

			if jwksClientCacheDuration < minJwksClientCacheDuration {
				minJwksClientCacheDuration = jwksClientCacheDuration
			}
		}

		if err := i.oidcCache.SetDefault(noNamespace, "nextRun", nextRun); err != nil {
			i.Logger().Error("error setting oidc cache", "err", err)
		}

		if minJwksClientCacheDuration < math.MaxInt64 {
			// the OIDC JWKS endpoint returns a Cache-Control HTTP header time between
			// 0 and the minimum verificationTTL or minimum rotationPeriod out of all
			// keys, whichever value is lower.
			//
			// This smooths calls from services validating JWTs to Vault, while
			// ensuring that operators can assert that servers honoring the
			// Cache-Control header will always have a superset of all valid keys, and
			// not trust any keys longer than a jwksCacheControlMaxAge duration after a
			// key is rotated out of signing use
			if err := i.oidcCache.SetDefault(noNamespace, "jwksCacheControlMaxAge", minJwksClientCacheDuration); err != nil {
				i.Logger().Error("error setting jwksCacheControlMaxAge in oidc cache", "err", err)
			}
		}

	}
}

func newOIDCCache(defaultExpiration, cleanupInterval time.Duration) *oidcCache {
	return &oidcCache{
		c: cache.New(defaultExpiration, cleanupInterval),
	}
}

func (c *oidcCache) nskey(ns *namespace.Namespace, key string) string {
	return fmt.Sprintf("v0:%s:%s", ns.ID, key)
}

func (c *oidcCache) Get(ns *namespace.Namespace, key string) (interface{}, bool, error) {
	if ns == nil {
		return nil, false, errNilNamespace
	}
	v, found := c.c.Get(c.nskey(ns, key))
	return v, found, nil
}

func (c *oidcCache) SetDefault(ns *namespace.Namespace, key string, obj interface{}) error {
	if ns == nil {
		return errNilNamespace
	}
	c.c.SetDefault(c.nskey(ns, key), obj)

	return nil
}

func (c *oidcCache) Delete(ns *namespace.Namespace, key string) error {
	if ns == nil {
		return errNilNamespace
	}
	c.c.Delete(c.nskey(ns, key))

	return nil
}

func (c *oidcCache) Flush(ns *namespace.Namespace) error {
	if ns == nil {
		return errNilNamespace
	}

	// Remove all items from the provided namespace as well as the shared, "no namespace" section.
	for itemKey := range c.c.Items() {
		if isTargetNamespacedKey(itemKey, []string{noNamespace.ID, ns.ID}) {
			c.c.Delete(itemKey)
		}
	}

	return nil
}

// isTargetNamespacedKey returns true for a properly constructed namespaced key (<version>:<nsID>:<key>)
// where <nsID> matches any targeted nsID
func isTargetNamespacedKey(nskey string, nsTargets []string) bool {
	split := strings.Split(nskey, ":")
	return len(split) >= 3 && strutil.StrListContains(nsTargets, split[1])
}
