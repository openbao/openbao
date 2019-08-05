package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/jcmturner/gokrb5.v5/credentials"
	"gopkg.in/jcmturner/gokrb5.v5/gssapi"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"gopkg.in/jcmturner/gokrb5.v5/service"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"authorization": {
				Type:        framework.TypeString,
				Description: `SPNEGO Authorization header. Required.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathLoginGet,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
			},
		},
	}
}

func parseKeytab(stringKeytab string) (*keytab.Keytab, error) {
	binary, err := base64.StdEncoding.DecodeString(stringKeytab)
	if err != nil {
		return nil, err
	}
	kt, err := keytab.Parse(binary)
	if err != nil {
		return nil, err
	}
	return &kt, nil
}

func spnegoKrb5Authenticate(kt keytab.Keytab, sa string, authorization []byte, remoteAddr string) (*credentials.Credentials, error) {
	var spnego gssapi.SPNEGO
	if err := spnego.Unmarshal(authorization); err != nil || !spnego.Init {
		return nil, fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
	}
	if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) && !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDMSLegacyKRB5) {
		return nil, errors.New("SPNEGO OID of MechToken is not of type KRB5")
	}

	var mt gssapi.MechToken
	if err := mt.Unmarshal(spnego.NegTokenInit.MechToken); err != nil {
		return nil, fmt.Errorf("SPNEGO error unmarshaling MechToken: %v", err)
	}
	if !mt.IsAPReq() {
		return nil, errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
	}

	// The first return value here is a boolean reflecting whether the request is valid;
	// however, this value is redundant because if the error is nil, the request is valid,
	// but if it's populated, the request is invalid. Hence, it's ignored here because we
	// only need to error if the error is populated, and that knowledge can be encapsulated
	// here.
	_, creds, err := service.ValidateAPREQ(mt.APReq, kt, sa, remoteAddr, false)
	if err != nil {
		return nil, err
	}
	return &creds, nil
}

func (b *backend) pathLoginGet(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Auth: &logical.Auth{},
		Headers: map[string][]string{
			"www-authenticate": {"Negotiate"},
		},
	}, logical.CodedError(401, "authentication required")
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	kerbCfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if kerbCfg == nil {
		return nil, errors.New("backend kerberos not configured")
	}

	kt, err := parseKeytab(kerbCfg.Keytab)
	if err != nil {
		return nil, err
	}

	ldapCfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, err
	}
	if ldapCfg == nil {
		return nil, errors.New("ldap backend not configured")
	}

	// Check for a CIDR match.
	if len(ldapCfg.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, ldapCfg.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	ldapClient := ldaputil.Client{
		Logger: b.Logger(),
		LDAP:   ldaputil.NewLDAP(),
	}

	ldapConnection, err := ldapClient.DialLDAP(ldapCfg.ConfigEntry)
	if err != nil {
		return nil, fmt.Errorf("could not connect to LDAP: %v", err)
	}
	if ldapConnection == nil {
		return nil, errors.New("invalid connection returned from LDAP dial")
	}

	// Clean ldap connection
	defer ldapConnection.Close()

	authorizationString := ""
	authorizationHeaders := req.Headers["Authorization"]
	if len(authorizationHeaders) > 0 {
		authorizationString = authorizationHeaders[0]
	} else {
		authorizationString = d.Get("authorization").(string)
	}

	s := strings.SplitN(authorizationString, " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		return b.pathLoginGet(ctx, req, d)
	}
	authorization, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode authorization: %v", err)
	}

	creds, err := spnegoKrb5Authenticate(*kt, kerbCfg.ServiceAccount, authorization, req.Connection.RemoteAddr)
	if err != nil {
		return nil, err
	}

	if len(ldapCfg.BindPassword) > 0 {
		err = ldapConnection.Bind(ldapCfg.BindDN, ldapCfg.BindPassword)
	} else {
		err = ldapConnection.UnauthenticatedBind(ldapCfg.BindDN)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP bind failed: %v", err)
	}

	userBindDN, err := ldapClient.GetUserBindDN(ldapCfg.ConfigEntry, ldapConnection, creds.Username)
	if err != nil {
		return nil, err
	}
	b.Logger().Debug("auth/ldap: User BindDN fetched", "username", creds.Username, "binddn", userBindDN)

	userDN, err := ldapClient.GetUserDN(ldapCfg.ConfigEntry, ldapConnection, userBindDN)
	if err != nil {
		return nil, err
	}

	ldapGroups, err := ldapClient.GetLdapGroups(ldapCfg.ConfigEntry, ldapConnection, userDN, creds.Username)
	if err != nil {
		return nil, err
	}
	b.Logger().Debug("auth/ldap: Groups fetched from server", "num_server_groups", len(ldapGroups), "server_groups", ldapGroups)

	var allGroups []string
	// Merge local and LDAP groups
	allGroups = append(allGroups, ldapGroups...)

	// Retrieve policies
	var policies []string
	for _, groupName := range allGroups {
		group, err := b.Group(ctx, req.Storage, groupName)
		if err != nil {
			b.Logger().Warn(fmt.Sprintf("unable to retrieve %s: %s", groupName, err.Error()))
			continue
		}
		if group == nil {
			b.Logger().Warn(fmt.Sprintf("unable to find %s, does not currently exist", groupName))
			continue
		}
		policies = append(policies, group.Policies...)
	}
	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies, true)

	auth := &logical.Auth{
		InternalData: map[string]interface{}{},
		Policies:     policies,
		Metadata: map[string]string{
			"user":  creds.Username,
			"realm": creds.Realm,
		},
		DisplayName: creds.Username,
		Alias:       &logical.Alias{Name: creds.Username},
		LeaseOptions: logical.LeaseOptions{
			Renewable: false,
		},
	}

	ldapCfg.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}
