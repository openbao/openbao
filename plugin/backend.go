package kerberosauth

import (
	"encoding/json"
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
			SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathLogin(b),
			},
			// pathsRole(b)
		),
	}

	return b
}

func (b *KerberosBackend) config(s logical.Storage) (*kerberosConfig, error) {
	raw, err := s.Get("config")
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	conf := &kerberosConfig{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	// TODO: extra parsing?

	return conf, nil
}

var backendHelp string = `
The Kerberos Auth Backend allows authentication via Kerberos SPNEGO.
`
