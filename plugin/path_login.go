package kerberosauth

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"gopkg.in/jcmturner/gokrb5.v3/gssapi"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/service"
)

func pathLogin(b *KerberosBackend) *framework.Path {
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

func (b *KerberosBackend) pathLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// TODO: move this in a function return parsed keytab
	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("Could not load backend configuration")
	}
	binary, err := base64.StdEncoding.DecodeString(config.Keytab)
	if err != nil {
		return nil, err
	}
	kt, err := keytab.Parse(binary)
	if err != nil {
		return nil, err
	}
	log.Printf("Kt version: %d", kt.Version)
	log.Printf("Kt len: %d", len(kt.Entries))
	for i, v := range kt.Entries {
		log.Printf("Kt entry %d: Principal realm %s components %s", i, v.Principal.Realm, v.Principal.Components)
		log.Printf("Kt entry %d: TS %s KVNO %d, Key type %d", i, v.Timestamp, v.KVNO, v.Key.KeyType)
	}

	// SPNEGOKRB5Authenticate
	// TODO: move into function returning cred, err
	authorization := d.Get("authorization").(string)
	//s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	log.Println(authorization)
	s := strings.SplitN(authorization, " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		return nil, errors.New("Invalid Authorization header")
	}
	binToken, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		// TODO: better error? how to combine errors? "Could not decode Authorization header"
		return nil, err
	}

	var spnego gssapi.SPNEGO
	err = spnego.Unmarshal(binToken)
	if !spnego.Init {
		//rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO negotiation token is not a NegTokenInit: %v", r.RemoteAddr, err))
		log.Println(err)
		return nil, errors.New("SPNEGO negotiation token is not a NegTokenInit")
	}
	if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) && !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDMSLegacyKRB5) {
		return nil, errors.New("SPNEGO OID of MechToken is not of type KRB5")
	}

	var mt gssapi.MechToken
	err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
	if err != nil {
		//rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error unmarshaling MechToken: %v", r.RemoteAddr, err))
		return nil, errors.New("SPNEGO error unmarshaling MechToken")
	}
	if !mt.IsAPReq() {
		//rejectSPNEGO(w, l, fmt.Sprintf("%v - MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE", r.RemoteAddr))
		return nil, errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
	}

	// TODO: get remote addr somehow? is it even important?
	remoteAddr := "wint-dev-vm169"
	ok, creds, err := service.ValidateAPREQ(mt.APReq, kt, config.ServiceAccount, remoteAddr)
	if !ok {
		if err != nil {
			return nil, err
		} else {
			return nil, errors.New("Kerberos authentication failed")
		}
	}

	// Use nicer error codes?
	//return nil, logical.ErrPermissionDenied

	ttl, _, err := b.SanitizeTTLStr("30s", "1h")
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			// TODO: extra fields?
			InternalData: map[string]interface{}{
				"secret_value": "abcd1234",
			},
			Policies: []string{"my-policy", "other-policy"},
			Metadata: map[string]string{
				"fruit": "banana",
				"user":  creds.Username,
				// TODO: think about which ones we want here
				"realm":      creds.Realm,
				"cname":      creds.CName.GetPrincipalNameString(),
				"auth_time":  creds.AuthTime().String(),
				"session_id": creds.SessionID(),
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
				Renewable: true,
			},
		},
	}, nil
}

func (b *KerberosBackend) pathRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	ttl, maxTTL, err := b.SanitizeTTLStr("30s", "1h")
	if err != nil {
		return nil, err
	}

	return framework.LeaseExtend(ttl, maxTTL, b.System())(req, d)
}
