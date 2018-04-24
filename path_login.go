package kerberos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"gopkg.in/jcmturner/gokrb5.v4/credentials"
	"gopkg.in/jcmturner/gokrb5.v4/gssapi"
	"gopkg.in/jcmturner/gokrb5.v4/keytab"
	"gopkg.in/jcmturner/gokrb5.v4/service"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"authorization": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `SPNEGO Authorization header. Required.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
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

func spnegoKrb5Authenticate(kt keytab.Keytab, sa string, authorization []byte, remoteAddr string) (bool, *credentials.Credentials, error) {
	var spnego gssapi.SPNEGO
	err := spnego.Unmarshal(authorization)
	if err != nil || !spnego.Init {
		return false, nil, fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
	}
	if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) && !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDMSLegacyKRB5) {
		return false, nil, errors.New("SPNEGO OID of MechToken is not of type KRB5")
	}

	var mt gssapi.MechToken
	err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
	if err != nil {
		return false, nil, fmt.Errorf("SPNEGO error unmarshaling MechToken: %v", err)
	}
	if !mt.IsAPReq() {
		return false, nil, errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
	}

	ok, creds, err := service.ValidateAPREQ(mt.APReq, kt, sa, remoteAddr)
	return ok, &creds, err
}

func (b *backend) pathLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("Could not load backend configuration")
	}

	kt, err := parseKeytab(config.Keytab)
	if err != nil {
		return nil, fmt.Errorf("Could not load keytab: %v", err)
	}

	ldapConfig, err := b.ConfigLdap(req)
	if err != nil {
		return nil, err
	}
	if ldapConfig == nil {
		return nil, errors.New("ldap backend not configured")
	}

	ldapConnection, err := ldapConfig.DialLDAP()
	if err != nil {
		return nil, fmt.Errorf("Could not connect to LDAP: %v", err)
	}
	if ldapConnection == nil {
		return nil, errors.New("invalid connection returned from LDAP dial")
	}

	// Clean ldap connection
	defer ldapConnection.Close()

	authorizationString := d.Get("authorization").(string)
	s := strings.SplitN(authorizationString, " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		return logical.ErrorResponse("Missing or invalid authorization"), nil
	}
	authorization, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, fmt.Errorf("Could not base64 decode authorization: %v", err)
	}

	ok, creds, err := spnegoKrb5Authenticate(*kt, config.ServiceAccount, authorization, req.Connection.RemoteAddr)
	if !ok {
		if err != nil {
			return nil, err
		} else {
			return logical.ErrorResponse("Kerberos authentication failed"), nil
		}
	}

	if len(ldapConfig.BindPassword) > 0 {
		err = ldapConnection.Bind(ldapConfig.BindDN, ldapConfig.BindPassword)
	} else {
		err = ldapConnection.UnauthenticatedBind(ldapConfig.BindDN)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP bind failed: %v", err)
	}

	userBindDN, err := b.getUserBindDN(ldapConfig, ldapConnection, creds.Username)
	if err != nil {
		return nil, err
	}

	if b.Logger().IsDebug() {
		b.Logger().Debug("auth/ldap: User BindDN fetched", "username", creds.Username, "binddn", userBindDN)
	}

	userDN, err := b.getUserDN(ldapConfig, ldapConnection, userBindDN)
	if err != nil {
		return nil, err
	}

	ldapGroups, err := b.getLdapGroups(ldapConfig, ldapConnection, userDN, creds.Username)
	if err != nil {
		return nil, err
	}
	if b.Logger().IsDebug() {
		b.Logger().Debug("auth/ldap: Groups fetched from server", "num_server_groups", len(ldapGroups), "server_groups", ldapGroups)
	}

	var allGroups []string
	// Merge local and LDAP groups
	allGroups = append(allGroups, ldapGroups...)

	// Retrieve policies
	var policies []string
	for _, groupName := range allGroups {
		group, err := b.Group(req.Storage, groupName)
		if err == nil && group != nil {
			policies = append(policies, group.Policies...)
		}
	}
	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies, true)

	return &logical.Response{
		Auth: &logical.Auth{
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
		},
	}, nil
}
