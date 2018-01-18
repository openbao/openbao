package kerberosauth

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type KerberosBackend struct {
	*framework.Backend
}

func Factory(c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(c); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(c *logical.BackendConfig) *KerberosBackend {
	b := &KerberosBackend{}

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathRenew,
		BackendType: logical.TypeCredential,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			//SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				// pathConfig(b),
				pathLogin(b),
			},
			// pathsRole(b)
		),
	}

	return b
}

var backendHelp string = `
The Kerberos Auth Backend allows authentication via Kerberos SPNEGO.
`
