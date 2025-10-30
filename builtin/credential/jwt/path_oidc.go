// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/oauth2"
)

const (
	oidcRequestTimeout         = 10 * time.Minute
	oidcRequestCleanupInterval = 1 * time.Minute
)

const (
	// OIDC error prefixes. These are searched for specifically by the UI, so any
	// changes to them must be aligned with a UI change.
	errLoginFailed       = "Vault login failed."
	errNoResponse        = "No response from provider."
	errTokenVerification = "Token verification failed."
	errNotOIDCFlow       = "OIDC login is not configured for this mount"

	noCode = "no_code"
)

// oidcRequest represents a single OIDC authentication flow. It is created when
// an authURL is requested. It is uniquely identified by a state, which is passed
// throughout the multiple interactions needed to complete the flow.
type oidcRequest struct {
	oidc.Request

	rolename string
	code     string
	idToken  string

	// clientNonce is used between Vault and the client/application (e.g. CLI) making the request,
	// and is unrelated to the OIDC nonce above. It is optional.
	clientNonce string

	// this is for storing the response in direct callback mode
	auth *logical.Auth

	// the device flow code
	deviceCode string
}

func pathOIDC(b *jwtAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `oidc/callback`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixJWTOIDC,
				OperationVerb:   "callback",
			},

			Fields: map[string]*framework.FieldSchema{
				"state": {
					Type:  framework.TypeString,
					Query: true,
				},
				"code": {
					Type:  framework.TypeString,
					Query: true,
				},
				"id_token": {
					Type: framework.TypeString,
					// This one is not "Query: true" as it is only consumed by the UpdateOperation,
					// not the ReadOperation
				},
				"client_nonce": {
					Type:  framework.TypeString,
					Query: true,
				},
				"error_description": {
					Type: framework.TypeString,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCallback,
					Summary:  "Callback endpoint to complete an OIDC login.",

					// state is cached so don't process OIDC logins on perf standbys
					ForwardPerformanceStandby: true,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathCallbackPost,
					Summary:  "Callback endpoint to handle form_posts.",

					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "form-post",
					},

					// state is cached so don't process OIDC logins on perf standbys
					ForwardPerformanceStandby: true,
				},
			},
		},
		{
			Pattern: `oidc/poll`,
			Fields: map[string]*framework.FieldSchema{
				"state": {
					Type: framework.TypeString,
				},
				"client_nonce": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathPoll,
					Summary:  "Poll endpoint to complete an OIDC login.",

					// state is cached so don't process OIDC logins on perf standbys
					ForwardPerformanceStandby: true,
				},
			},
		},
		{
			Pattern: `oidc/auth_url`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixJWTOIDC,
				OperationVerb:   "request",
				OperationSuffix: "authorization-url",
			},

			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeLowerCaseString,
					Description: "The role to issue an OIDC authorization URL against.",
				},
				"redirect_uri": {
					Type:        framework.TypeString,
					Description: "The OAuth redirect_uri to use in the authorization URL.  Not needed with device flow.",
				},
				"client_nonce": {
					Type:        framework.TypeString,
					Description: "Client-provided nonce that must match during callback, if present. Required only in direct callback mode.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.authURL,
					Summary:  "Request an authorization URL to start an OIDC login flow.",

					// state is cached so don't process OIDC logins on perf standbys
					ForwardPerformanceStandby: true,
				},
			},
		},
	}
}

func (b *jwtAuthBackend) pathCallbackPost(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(errLoginFailed + " Could not load configuration."), nil
	}

	if config.OIDCResponseMode != responseModeFormPost {
		return logical.RespondWithStatusCode(nil, req, http.StatusMethodNotAllowed)
	}

	stateID := d.Get("state").(string)
	code := d.Get("code").(string)
	idToken := d.Get("id_token").(string)

	resp := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/html",
			logical.HTTPStatusCode:  http.StatusOK,
		},
	}

	// Store the provided code and/or token into its OIDC request, which must already exist.
	oidcReq := b.getOIDCRequest(stateID)
	if oidcReq == nil {
		resp.Data[logical.HTTPRawBody] = []byte(errorHTML(errLoginFailed, "Expired or missing OAuth state."))
		resp.Data[logical.HTTPStatusCode] = http.StatusBadRequest
	} else {
		oidcReq.code = code
		oidcReq.idToken = idToken
		b.setOIDCRequest(stateID, oidcReq)
		mount := parseMount(oidcReq.RedirectURL())
		if mount == "" {
			resp.Data[logical.HTTPRawBody] = []byte(errorHTML(errLoginFailed, "Invalid redirect path."))
			resp.Data[logical.HTTPStatusCode] = http.StatusBadRequest
		} else {
			resp.Data[logical.HTTPRawBody] = []byte(formpostHTML(mount, noCode, stateID))
		}
	}

	return resp, nil
}

func loginFailedResponse(useHttp bool, msg string) *logical.Response {
	if !useHttp {
		return logical.ErrorResponse(errLoginFailed + " " + msg)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/html",
			logical.HTTPStatusCode:  http.StatusBadRequest,
			logical.HTTPRawBody:     []byte(errorHTML(errLoginFailed, msg)),
		},
	}
}

func (b *jwtAuthBackend) pathCallback(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(errLoginFailed + " Could not load configuration"), nil
	}

	stateID := d.Get("state").(string)

	oidcReq := b.getOIDCRequest(stateID)
	if oidcReq == nil || oidcReq.auth != nil {
		return logical.ErrorResponse(errLoginFailed + " Expired or missing OAuth state."), nil
	}

	deleteRequest := true
	defer func() {
		if deleteRequest {
			b.deleteOIDCRequest(stateID)
		}
	}()

	roleName := oidcReq.rolename
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		b.deleteOIDCRequest(stateID)
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(errLoginFailed + " Role could not be found"), nil
	}

	useHttp := false
	if role.CallbackMode == callbackModeDirect {
		useHttp = true
		// save request for poll
		deleteRequest = false
	}

	errorDescription := d.Get("error_description").(string)
	if errorDescription != "" {
		return loginFailedResponse(useHttp, errorDescription), nil
	}

	clientNonce := d.Get("client_nonce").(string)

	// If a client_nonce was provided at the start of the auth process as part of the auth_url
	// request, require that it is present and matching during the callback phase
	// unless using the direct callback mode (when we instead check in poll).
	if oidcReq.clientNonce != "" && clientNonce != oidcReq.clientNonce && role.CallbackMode != callbackModeDirect {
		return logical.ErrorResponse("invalid client_nonce"), nil
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	provider, err := b.getProvider(config)
	if err != nil {
		return nil, fmt.Errorf("error getting provider for login operation: %w", err)
	}

	oidcCtx, err := b.createCAContext(ctx, config.OIDCDiscoveryCAPEM, config.OverrideAllowedServerNames)
	if err != nil {
		return nil, fmt.Errorf("error preparing context for login operation: %w", err)
	}

	var token *oidc.Tk
	var tokenSource oauth2.TokenSource

	code := d.Get("code").(string)
	if code == noCode {
		code = oidcReq.code
	}

	if code == "" {
		if oidcReq.idToken == "" {
			return loginFailedResponse(useHttp, "No code or id_token received."), nil
		}

		// Verify the ID token received from the authentication response.
		rawToken := oidc.IDToken(oidcReq.idToken)
		if _, err := provider.VerifyIDToken(ctx, rawToken, oidcReq); err != nil {
			return logical.ErrorResponse("%s %s", errTokenVerification, err.Error()), nil
		}

		token, err = oidc.NewToken(rawToken, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating oidc token: %w", err)
		}
	} else {
		// Exchange the authorization code for an ID token and access token.
		// ID token verification takes place in provider.Exchange.
		token, err = provider.Exchange(ctx, oidcReq, stateID, code)
		if err != nil {
			return loginFailedResponse(useHttp, fmt.Sprintf("Error exchanging oidc code: %q.", err.Error())), nil
		}

		tokenSource = token.StaticTokenSource()
	}

	return b.processToken(ctx, req, config, oidcCtx, provider, roleName, role, token, tokenSource, stateID, oidcReq, useHttp)
}

// Continue processing a token after it has been received from the
// OIDC provider from either code or device authorization flows
func (b *jwtAuthBackend) processToken(ctx context.Context, req *logical.Request, config *jwtConfig, oidcCtx context.Context, provider *oidc.Provider, roleName string, role *jwtRole, token *oidc.Tk, tokenSource oauth2.TokenSource, stateID string, oidcReq *oidcRequest, useHttp bool) (*logical.Response, error) {
	if role.VerboseOIDCLogging {
		loggedToken := "invalid token format"

		parts := strings.Split(string(token.IDToken()), ".")
		if len(parts) == 3 {
			// strip signature from logged token
			loggedToken = fmt.Sprintf("%s.%s.xxxxxxxxxxx", parts[0], parts[1])
		}

		b.Logger().Debug("OIDC provider response", "id_token", loggedToken)
	}

	// Parse claims from the ID token payload.
	var allClaims map[string]interface{}
	if err := token.IDToken().Claims(&allClaims); err != nil {
		return nil, err
	}

	if claimNonce, ok := allClaims["nonce"]; ok {
		if oidcReq != nil && claimNonce != oidcReq.Nonce() {
			return loginFailedResponse(useHttp, "invalid ID token nonce."), nil
		}
		delete(allClaims, "nonce")
	}

	// Get the subject claim for bound subject and user info validation
	var subject string
	if subStr, ok := allClaims["sub"].(string); ok {
		subject = subStr
	}

	if role.BoundSubject != "" && role.BoundSubject != subject {
		return loginFailedResponse(useHttp, "sub claim does not match bound subject"), nil
	}

	// If we have a tokenSource, attempt to fetch information from the /userinfo endpoint
	// and merge it with the existing claims data. A failure to fetch additional information
	// from this endpoint will not invalidate the authorization flow.
	if tokenSource != nil {
		if err := provider.UserInfo(ctx, tokenSource, subject, &allClaims); err != nil {
			logFunc := b.Logger().Warn
			if strings.Contains(err.Error(), "user info endpoint is not supported") {
				logFunc = b.Logger().Info
			}
			logFunc("error reading /userinfo endpoint", "error", err)
		}
	}

	// Also fetch any requested extra oauth2 metadata
	oauth2Metadata := make(map[string]string)
	for _, mdname := range role.Oauth2Metadata {
		var md string
		switch mdname {
		case "id_token":
			md = string(token.IDToken())
		case "refresh_token":
			md = string(token.RefreshToken())
		case "access_token":
			md = string(token.AccessToken())
		default:
			// previously validated so this should never happen
			return logical.ErrorResponse(errLoginFailed + " Unrecognized oauth2 metadata name " + mdname), nil
		}
		oauth2Metadata[mdname] = md
	}

	if role.VerboseOIDCLogging {
		if c, err := json.Marshal(allClaims); err == nil {
			b.Logger().Debug("OIDC provider response", "claims", string(c))
		} else {
			b.Logger().Debug("OIDC provider response", "marshalling error", err.Error())
		}
	}

	alias, groupAliases, err := b.createIdentity(ctx, allClaims, roleName, role, tokenSource)
	if err != nil {
		return loginFailedResponse(useHttp, err.Error()), nil
	}

	if err := validateBoundClaims(b.Logger(), role.BoundClaimsType, role.BoundClaims, allClaims); err != nil {
		return loginFailedResponse(useHttp, fmt.Sprintf("error validating claims: %s", err.Error())), nil
	}

	tokenMetadata := make(map[string]string)
	for k, v := range alias.Metadata {
		tokenMetadata[k] = v
	}
	for k, v := range oauth2Metadata {
		tokenMetadata["oauth2_"+k] = v
	}

	auth := &logical.Auth{
		Policies:     role.Policies,
		DisplayName:  alias.Name,
		Period:       role.Period,
		NumUses:      role.NumUses,
		Alias:        alias,
		GroupAliases: groupAliases,
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: tokenMetadata,
		LeaseOptions: logical.LeaseOptions{
			Renewable: true,
			TTL:       role.TTL,
			MaxTTL:    role.MaxTTL,
		},
		BoundCIDRs: role.BoundCIDRs,
	}

	if err := role.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	if err := role.maybeTemplatePolicies(auth, allClaims); err != nil {
		return nil, err
	}

	resp := &logical.Response{}
	if useHttp {
		oidcReq.auth = auth
		b.setOIDCRequest(stateID, oidcReq)
		resp.Data = map[string]interface{}{
			logical.HTTPContentType: "text/html",
			logical.HTTPStatusCode:  http.StatusOK,
			logical.HTTPRawBody:     []byte(successHTML),
		}
	} else {
		resp.Auth = auth
	}

	return resp, nil
}

// second half of the client API for direct and device callback modes
func (b *jwtAuthBackend) pathPoll(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	stateID := d.Get("state").(string)
	oidcReq := b.getOIDCRequest(stateID)
	if oidcReq == nil {
		return logical.ErrorResponse(errLoginFailed + " Expired or missing OAuth state."), nil
	}

	deleteRequest := true
	defer func() {
		if deleteRequest {
			b.deleteOIDCRequest(stateID)
		}
	}()

	clientNonce := d.Get("client_nonce").(string)

	if oidcReq.clientNonce != "" && clientNonce != oidcReq.clientNonce {
		return logical.ErrorResponse("invalid client_nonce"), nil
	}

	roleName := oidcReq.rolename
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(errLoginFailed + " Role could not be found"), nil
	}

	if role.CallbackMode == callbackModeDevice {
		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse(errLoginFailed + " Could not load configuration"), nil
		}

		caCtx, err := b.createCAContext(ctx, config.OIDCDiscoveryCAPEM, config.OverrideAllowedServerNames)
		if err != nil {
			return nil, err
		}
		provider, err := b.getProvider(config)
		if err != nil {
			return nil, fmt.Errorf("error getting provider for poll operation: %w", err)
		}

		values := url.Values{
			"client_id":     {config.OIDCClientID},
			"client_secret": {config.OIDCClientSecret},
			"device_code":   {oidcReq.deviceCode},
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		body, err := contactIssuer(caCtx, config.OIDCTokenURL, &values, true)
		if err != nil {
			return nil, fmt.Errorf("error polling for device authorization: %w", err)
		}

		var tokenOrError struct {
			*oauth2.Token
			Error string `json:"error,omitempty"`
		}
		err = json.Unmarshal(body, &tokenOrError)
		if err != nil {
			return nil, fmt.Errorf("error decoding issuer response while polling for token: %v; response: %v", err, string(body))
		}

		if tokenOrError.Error != "" {
			if tokenOrError.Error == "authorization_pending" || tokenOrError.Error == "slow_down" {
				// save request for another poll
				deleteRequest = false
				return logical.ErrorResponse(tokenOrError.Error), nil
			}
			return logical.ErrorResponse("authorization failed: %v", tokenOrError.Error), nil
		}

		extra := make(map[string]interface{})
		err = json.Unmarshal(body, &extra)
		if err != nil {
			// already been unmarshalled once, unlikely
			return nil, err
		}
		oauth2Token := tokenOrError.Token.WithExtra(extra)

		// idToken, ok := oauth2Token.Extra("id_token").(oidc.IDToken)
		rawToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return logical.ErrorResponse(errTokenVerification + " No id_token found in response."), nil
		}
		idToken := oidc.IDToken(rawToken)
		token, err := oidc.NewToken(idToken, tokenOrError.Token)
		if err != nil {
			return nil, fmt.Errorf("error creating oidc token: %w", err)
		}

		return b.processToken(ctx, req, config, caCtx, provider, roleName, role, token, oauth2.StaticTokenSource(oauth2Token), "", nil, false)
	}

	// else it's the direct callback mode
	if oidcReq.auth == nil {
		// save request for another poll
		deleteRequest = false
	}

	if oidcReq.auth == nil {
		// Return the same response as oauth 2.0 device flow in RFC8628
		return logical.ErrorResponse("authorization_pending"), nil
	}

	resp := &logical.Response{
		Auth: oidcReq.auth,
	}
	return resp, nil
}

// authURL returns a URL used for redirection to receive an authorization code.
// This path requires a role name, or that a default_role has been configured.
// Because this endpoint is unauthenticated, the response to invalid or non-OIDC
// roles is intentionally non-descriptive and will simply be an empty string.
func (b *jwtAuthBackend) authURL(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger()

	// default response for most error/invalid conditions
	resp := &logical.Response{
		Data: map[string]interface{}{
			"auth_url": "",
		},
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	if config.authType() != OIDCFlow {
		return logical.ErrorResponse(errNotOIDCFlow), nil
	}

	roleName := d.Get("role").(string)
	if roleName == "" {
		roleName = config.DefaultRole
	}
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	redirectURI := d.Get("redirect_uri").(string)

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	clientNonce := d.Get("client_nonce").(string)
	if clientNonce == "" &&
		(role.CallbackMode == callbackModeDirect ||
			role.CallbackMode == callbackModeDevice) {
		return logical.ErrorResponse("missing client_nonce"), nil
	}

	if role.CallbackMode == callbackModeDevice {
		caCtx, err := b.createCAContext(ctx, config.OIDCDiscoveryCAPEM, config.OverrideAllowedServerNames)
		if err != nil {
			return nil, err
		}

		// Discover the device url endpoint if not already known
		// This adds it to the cached config
		err = b.configDeviceAuthURL(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		// "openid" is a required scope for OpenID Connect flows
		scopes := append([]string{"openid"}, role.OIDCScopes...)

		values := url.Values{
			"client_id":     {config.OIDCClientID},
			"client_secret": {config.OIDCClientSecret},
			"scope":         {strings.Join(scopes, " ")},
		}
		body, err := contactIssuer(caCtx, config.OIDCDeviceAuthURL, &values, false)
		if err != nil {
			return nil, fmt.Errorf("error authorizing device: %w", err)
		}

		var deviceCode struct {
			DeviceCode              string `json:"device_code"`
			UserCode                string `json:"user_code"`
			VerificationURI         string `json:"verification_uri"`
			VerificationURIComplete string `json:"verification_uri_complete"`
			// Google and other old implementations use url instead of uri
			VerificationURL         string `json:"verification_url"`
			VerificationURLComplete string `json:"verification_url_complete"`
			Interval                int    `json:"interval"`
		}
		err = json.Unmarshal(body, &deviceCode)
		if err != nil {
			return nil, fmt.Errorf("error decoding issuer response to device auth: %v; response: %v", err, string(body))
		}
		// currently hashicorp/cap/oidc.NewRequest requires
		//  redirectURL to be non-empty so throw in place holder
		oidcReq, err := b.createOIDCRequest(config, role, roleName, "-", deviceCode.DeviceCode, clientNonce)
		if err != nil {
			logger.Warn("error generating OAuth state", "error", err)
			return resp, nil
		}

		if deviceCode.VerificationURIComplete != "" {
			resp.Data["auth_url"] = deviceCode.VerificationURIComplete
		} else if deviceCode.VerificationURLComplete != "" {
			resp.Data["auth_url"] = deviceCode.VerificationURLComplete
		} else {
			if deviceCode.VerificationURI != "" {
				resp.Data["auth_url"] = deviceCode.VerificationURI
			} else {
				resp.Data["auth_url"] = deviceCode.VerificationURL
			}
			resp.Data["user_code"] = deviceCode.UserCode
		}
		resp.Data["state"] = oidcReq.State()
		interval := 5
		if role.PollInterval != 0 {
			interval = role.PollInterval
		} else if deviceCode.Interval != 0 {
			interval = deviceCode.Interval
		}
		resp.Data["poll_interval"] = fmt.Sprintf("%d", interval)
		return resp, nil
	}

	if redirectURI == "" {
		return logical.ErrorResponse("missing redirect_uri"), nil
	}

	// If namespace will be passed around in oidcReq, and it has been provided as
	// a redirectURI query parameter, remove it from redirectURI, and append it
	// to the oidcReq (later in this function)
	namespace := ""
	if config.NamespaceInState {
		inputURI, err := url.Parse(redirectURI)
		if err != nil {
			return resp, nil
		}
		qParam := inputURI.Query()
		namespace = qParam.Get("namespace")
		if len(namespace) > 0 {
			qParam.Del("namespace")
			inputURI.RawQuery = qParam.Encode()
			redirectURI = inputURI.String()
		}
	}

	if !validRedirect(redirectURI, role.AllowedRedirectURIs) {
		logger.Warn("unauthorized redirect_uri", "redirect_uri", redirectURI)
		return resp, nil
	}

	// If configured for form_post, redirect directly to Vault instead of the UI,
	// if this was initiated by the UI (which currently has no knowledge of mode).
	//
	// TODO: it would be better to convey this to the UI and have it send the
	// correct URL directly.
	if config.OIDCResponseMode == responseModeFormPost {
		redirectURI = strings.Replace(redirectURI, "ui/vault", "v1", 1)
	}

	provider, err := b.getProvider(config)
	if err != nil {
		logger.Warn("error getting provider for login operation", "error", err)
		return resp, nil
	}

	oidcReq, err := b.createOIDCRequest(config, role, roleName, redirectURI, "", clientNonce)
	if err != nil {
		logger.Warn("error generating OAuth state", "error", err)
		return resp, nil
	}

	urlStr, err := provider.AuthURL(ctx, oidcReq)
	if err != nil {
		logger.Warn("error generating auth URL", "error", err)
		return resp, nil
	}

	// embed namespace in oidcReq in the auth_url
	if config.NamespaceInState && len(namespace) > 0 {
		stateWithNamespace := fmt.Sprintf("%s,ns=%s", oidcReq.State(), namespace)
		urlStr = strings.Replace(urlStr, oidcReq.State(), url.QueryEscape(stateWithNamespace), 1)
	}

	resp.Data["auth_url"] = urlStr
	if role.CallbackMode == callbackModeDirect {
		resp.Data["state"] = oidcReq.State()
		interval := 5
		if role.PollInterval != 0 {
			interval = role.PollInterval
		}
		resp.Data["poll_interval"] = fmt.Sprintf("%d", interval)
	}

	return resp, nil
}

// createOIDCRequest makes an expiring request object, associated with a random state ID
// that is passed throughout the OAuth process. A nonce is also included in the auth process.
func (b *jwtAuthBackend) createOIDCRequest(config *jwtConfig, role *jwtRole, rolename, redirectURI, deviceCode string, clientNonce string) (*oidcRequest, error) {
	options := []oidc.Option{
		oidc.WithAudiences(role.BoundAudiences...),
		oidc.WithScopes(role.OIDCScopes...),
	}

	if config.hasType(responseTypeIDToken) {
		options = append(options, oidc.WithImplicitFlow())
	} else if config.hasType(responseTypeCode) {
		v, err := oidc.NewCodeVerifier()
		if err != nil {
			return nil, fmt.Errorf("error creating code challenge: %w", err)
		}

		options = append(options, oidc.WithPKCE(v))
	}

	if role.MaxAge > 0 {
		options = append(options, oidc.WithMaxAge(uint(role.MaxAge.Seconds())))
	}

	request, err := oidc.NewRequest(oidcRequestTimeout, redirectURI, options...)
	if err != nil {
		return nil, err
	}

	oidcReq := &oidcRequest{
		Request:     request,
		rolename:    rolename,
		clientNonce: clientNonce,
		deviceCode:  deviceCode,
	}
	b.oidcRequests.SetDefault(request.State(), oidcReq)

	return oidcReq, nil
}

func (b *jwtAuthBackend) setOIDCRequest(stateID string, oidcReq *oidcRequest) {
	b.oidcRequests.SetDefault(stateID, oidcReq)
}

func (b *jwtAuthBackend) getOIDCRequest(stateID string) *oidcRequest {
	if requestRaw, ok := b.oidcRequests.Get(stateID); ok {
		return requestRaw.(*oidcRequest)
	}
	return nil
}

func (b *jwtAuthBackend) deleteOIDCRequest(stateID string) {
	b.oidcRequests.Delete(stateID)
}

// validRedirect checks whether uri is in allowed using special handling for loopback uris.
// Ref: https://tools.ietf.org/html/rfc8252#section-7.3
func validRedirect(uri string, allowed []string) bool {
	inputURI, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// if uri isn't a loopback, just string search the allowed list
	if !strutil.StrListContains([]string{"localhost", "127.0.0.1", "::1"}, inputURI.Hostname()) {
		return strutil.StrListContains(allowed, uri)
	}

	// otherwise, search for a match in a port-agnostic manner, per the OAuth RFC.
	inputURI.Host = inputURI.Hostname()

	for _, a := range allowed {
		allowedURI, err := url.Parse(a)
		if err != nil {
			return false
		}
		allowedURI.Host = allowedURI.Hostname()

		if inputURI.String() == allowedURI.String() {
			return true
		}
	}

	return false
}

// parseMount attempts to extract the mount path from a redirect URI.
func parseMount(redirectURI string) string {
	parts := strings.Split(redirectURI, "/")

	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "v1" && parts[i+1] == "auth" {
			return parts[i+2]
		}
	}
	return ""
}
