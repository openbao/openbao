package kerberos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/gssapi"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/service"
)

func pathLogin(b *kerberosBackend) *framework.Path {
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

func (b *kerberosBackend) pathLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{},
			Policies:     []string{},
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
