package kubeauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

// defaultJWTIssuer is used to verify the iss header on the JWT if the config doesn't specify an issuer.
var defaultJWTIssuer = "kubernetes/serviceaccount"

// See https://datatracker.ietf.org/doc/html/rfc7518#section-3.
var supportedJwtAlgs = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
}

// pathLogin returns the path configurations for login endpoints
func pathLogin(b *kubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. This field is required`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account. This field is required.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.aliasLookahead,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

// pathLogin is used to authenticate to this backend
func (b *kubeAuthBackend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName, resp := b.getFieldValueStr(data, "role")
	if resp != nil {
		return resp, nil
	}

	jwtStr, resp := b.getFieldValueStr(data, "jwt")
	if resp != nil {
		return resp, nil
	}

	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name %q", roleName)), nil
	}

	// Check for a CIDR match.
	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	config, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("could not load backend configuration")
	}

	serviceAccount, err := b.parseAndValidateJWT(jwtStr, role, config)
	if err == jwt.ErrSignatureInvalid {
		b.Logger().Debug(`login unauthorized`, "err", err)
		return nil, logical.ErrPermissionDenied
	} else if err != nil {
		return nil, err
	}

	aliasName, err := b.getAliasName(role, serviceAccount)
	if err != nil {
		return nil, err
	}

	// look up the JWT token in the kubernetes API
	err = serviceAccount.lookup(ctx, b.httpClient, jwtStr, b.reviewFactory(config))

	if err != nil {
		b.Logger().Debug(`login unauthorized`, "err", err)
		return nil, logical.ErrPermissionDenied
	}

	uid, err := serviceAccount.uid()
	if err != nil {
		return nil, err
	}
	auth := &logical.Auth{
		Alias: &logical.Alias{
			Name: aliasName,
			Metadata: map[string]string{
				"service_account_uid":         uid,
				"service_account_name":        serviceAccount.name(),
				"service_account_namespace":   serviceAccount.namespace(),
				"service_account_secret_name": serviceAccount.SecretName,
			},
		},
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: map[string]string{
			"service_account_uid":         uid,
			"service_account_name":        serviceAccount.name(),
			"service_account_namespace":   serviceAccount.namespace(),
			"service_account_secret_name": serviceAccount.SecretName,
			"role":                        roleName,
		},
		DisplayName: fmt.Sprintf("%s-%s", serviceAccount.namespace(), serviceAccount.name()),
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *kubeAuthBackend) getFieldValueStr(data *framework.FieldData, param string) (string, *logical.Response) {
	val := data.Get(param).(string)
	if len(val) == 0 {
		return "", logical.ErrorResponse("missing %s", param)
	}
	return val, nil
}

func (b *kubeAuthBackend) getAliasName(role *roleStorageEntry, serviceAccount *serviceAccount) (string, error) {
	switch role.AliasNameSource {
	case aliasNameSourceSAUid, aliasNameSourceUnset:
		uid, err := serviceAccount.uid()
		if err != nil {
			return "", err
		}
		return uid, nil
	case aliasNameSourceSAName:
		ns, name := serviceAccount.namespace(), serviceAccount.name()
		if ns == "" || name == "" {
			return "", fmt.Errorf("service account namespace and name must be set")
		}
		return fmt.Sprintf("%s/%s", ns, name), nil
	default:
		return "", fmt.Errorf("unknown alias_name_source %q", role.AliasNameSource)
	}
}

// aliasLookahead returns the alias object with the SA UID from the JWT
// Claims.
// Only JWTs matching the specified role's configuration will be accepted as valid.
func (b *kubeAuthBackend) aliasLookahead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName, resp := b.getFieldValueStr(data, "role")
	if resp != nil {
		return resp, nil
	}

	jwtStr, resp := b.getFieldValueStr(data, "jwt")
	if resp != nil {
		return resp, nil
	}

	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name %q", roleName)), nil
	}

	config, err := b.loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("could not load backend configuration")
	}
	// validation of the JWT against the provided role ensures alias look ahead requests
	// are authentic.
	sa, err := b.parseAndValidateJWT(jwtStr, role, config)
	if err != nil {
		return nil, err
	}

	aliasName, err := b.getAliasName(role, sa)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: aliasName,
			},
		},
	}, nil
}

// parseAndVerifySignature parses the JWT token validating the signature against
// any of the keys passed in.
func (b *kubeAuthBackend) parseAndVerifySignature(token string, keys ...interface{}) (*jwt.Token, error) {
	for i, k := range keys {
		// only consider RSA & ECDSA signatures
		_, isEcdsa := k.(*ecdsa.PublicKey)
		_, isRsa := k.(*rsa.PublicKey)
		if !(isEcdsa || isRsa) {
			continue
		}
		result, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			return k, nil
		}, jwt.WithValidMethods(supportedJwtAlgs))
		if result != nil && err == nil {
			return result, nil
		}
		if err != nil && strings.ToLower(err.Error()) == strings.ToLower(jwt.ErrTokenExpired.Error()) {
			return nil, err
		}
		b.Logger().Debug(fmt.Sprintf("JWT signature did not validate with key %d, testing next key", i))
		// otherwise, try the next key
	}
	b.Logger().Debug("JWT signature did not validate with any keys")
	return nil, jwt.ErrSignatureInvalid
}

// parseAndValidateJWT is used to parse, validate and lookup the JWT token.
func (b *kubeAuthBackend) parseAndValidateJWT(jwtStr string, role *roleStorageEntry, config *kubeConfig) (*serviceAccount, error) {
	// Parse into JWT
	var token *jwt.Token
	var err error
	if len(config.PublicKeys) == 0 {
		// we don't verify the signature if we aren't configured with public keys
		token, _, err = jwt.NewParser().ParseUnverified(jwtStr, jwt.MapClaims{})
	} else {
		token, err = b.parseAndVerifySignature(jwtStr, config.PublicKeys...)
	}
	if err != nil {
		return nil, err
	}

	// do default claims validation (expiration, issued at, not before)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unsupported JWT claims type")
	}
	err = claims.Valid()
	if err != nil {
		return nil, err
	}

	sa := &serviceAccount{}

	// Decode claims into a service account object
	err = mapstructure.Decode(token.Claims, sa)
	if err != nil {
		return nil, err
	}

	// verify the namespace is allowed
	if len(role.ServiceAccountNamespaces) > 1 || role.ServiceAccountNamespaces[0] != "*" {
		if !strutil.StrListContainsGlob(role.ServiceAccountNamespaces, sa.namespace()) {
			return nil, logical.CodedError(http.StatusForbidden, "namespace not authorized")
		}
	}

	// verify the service account name is allowed
	if len(role.ServiceAccountNames) > 1 || role.ServiceAccountNames[0] != "*" {
		if !strutil.StrListContainsGlob(role.ServiceAccountNames, sa.name()) {
			return nil, logical.CodedError(http.StatusForbidden,
				fmt.Sprintf("service account name not authorized"))
		}
	}

	// perform ISS Claim validation if configured
	if !config.DisableISSValidation {
		// set the expected issuer to the default kubernetes issuer if the config doesn't specify it
		if config.Issuer != "" {
			if !claims.VerifyIssuer(config.Issuer, true) {
				return nil, logical.CodedError(http.StatusForbidden, "invalid token issuer")
			}
		} else {
			if !claims.VerifyIssuer(defaultJWTIssuer, true) {
				return nil, logical.CodedError(http.StatusForbidden, "invalid token issuer")
			}
		}
	}

	// validate the audience if the role expects it
	if role.Audience != "" {
		if !claims.VerifyAudience(role.Audience, true) {
			return nil, logical.CodedError(http.StatusForbidden, "invalid audience")
		}
	}
	// If we don't have any public keys to verify, return the sa and end early.
	if len(config.PublicKeys) == 0 {
		return sa, nil
	}

	return sa, nil
}

// serviceAccount holds the metadata from the JWT token and is used to lookup
// the JWT in the kubernetes API and compare the results.
type serviceAccount struct {
	Name       string   `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID        string   `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName string   `mapstructure:"kubernetes.io/serviceaccount/secret.name"`
	Namespace  string   `mapstructure:"kubernetes.io/serviceaccount/namespace"`
	Audience   []string `mapstructure:"aud"`

	// the JSON returned from reviewing a Projected Service account has a
	// different structure, where the information is in a sub-structure instead of
	// at the top level
	Kubernetes *projectedServiceToken `mapstructure:"kubernetes.io"`
	Expiration int64                  `mapstructure:"exp"`
	IssuedAt   int64                  `mapstructure:"iat"`
}

// uid returns the UID for the service account, preferring the projected service
// account value if found
// return an error when the UID is empty.
func (s *serviceAccount) uid() (string, error) {
	uid := s.UID
	if s.Kubernetes != nil && s.Kubernetes.ServiceAccount != nil {
		uid = s.Kubernetes.ServiceAccount.UID
	}

	if uid == "" {
		return "", errors.New("could not parse UID from claims")
	}
	return uid, nil
}

// name returns the name for the service account, preferring the projected
// service account value if found. This is "default" for projected service
// accounts
func (s *serviceAccount) name() string {
	if s.Kubernetes != nil && s.Kubernetes.ServiceAccount != nil {
		return s.Kubernetes.ServiceAccount.Name
	}
	return s.Name
}

// namespace returns the namespace for the service account, preferring the
// projected service account value if found
func (s *serviceAccount) namespace() string {
	if s.Kubernetes != nil {
		return s.Kubernetes.Namespace
	}
	return s.Namespace
}

type projectedServiceToken struct {
	Namespace      string        `mapstructure:"namespace"`
	Pod            *k8sObjectRef `mapstructure:"pod"`
	ServiceAccount *k8sObjectRef `mapstructure:"serviceaccount"`
}

type k8sObjectRef struct {
	Name string `mapstructure:"name"`
	UID  string `mapstructure:"uid"`
}

// lookup calls the TokenReview API in kubernetes to verify the token and secret
// still exist.
func (s *serviceAccount) lookup(ctx context.Context, client *http.Client, jwtStr string, tr tokenReviewer) error {
	r, err := tr.Review(ctx, client, jwtStr, s.Audience)
	if err != nil {
		return err
	}

	// Verify the returned metadata matches the expected data from the service
	// account.
	if s.name() != r.Name {
		return errors.New("JWT names did not match")
	}
	uid, err := s.uid()
	if err != nil {
		return err
	}
	if uid != r.UID {
		return errors.New("JWT UIDs did not match")
	}
	if s.namespace() != r.Namespace {
		return errors.New("JWT namepaces did not match")
	}

	return nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *kubeAuthBackend) pathLoginRenew() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := req.Auth.InternalData["role"].(string)
		if roleName == "" {
			return nil, fmt.Errorf("failed to fetch role_name during renewal")
		}

		b.l.RLock()
		defer b.l.RUnlock()

		// Ensure that the Role still exists.
		role, err := b.role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to validate role %s during renewal:%s", roleName, err)
		}
		if role == nil {
			return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
		}

		resp := &logical.Response{Auth: req.Auth}
		resp.Auth.TTL = role.TokenTTL
		resp.Auth.MaxTTL = role.TokenMaxTTL
		resp.Auth.Period = role.TokenPeriod
		return resp, nil
	}
}

const (
	pathLoginHelpSyn  = `Authenticates Kubernetes service accounts with Vault.`
	pathLoginHelpDesc = `
Authenticate Kubernetes service accounts.
`
)
