package kerberosauth

import (
	"crypto/subtle"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *KerberosBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Password. Required.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},
	}
}

func (b *KerberosBackend) pathLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	password := d.Get("password").(string)

	if subtle.ConstantTimeCompare([]byte(password), []byte("geheim")) != 1 {
		return nil, logical.ErrPermissionDenied
	}

	ttl, _, err := b.SanitizeTTLStr("30s", "1h")
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			// TODO: extra fields
			InternalData: map[string]interface{}{
				"secret_value": "abcd1234",
			},
			Policies: []string{"my-policy", "other-policy"},
			Metadata: map[string]string{
				"fruit": "banana",
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
