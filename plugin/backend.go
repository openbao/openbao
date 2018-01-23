package kerberosauth

import (
	"encoding/json"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath string = "config"
)

type kerberosBackend struct {
	*framework.Backend
}

func Factory(c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(c); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(c *logical.BackendConfig) *kerberosBackend {
	b := &kerberosBackend{}

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathRenew,
		BackendType: logical.TypeCredential,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			SealWrapStorage: []string{configPath},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathLogin(b),
			},
		),
	}

	return b
}

func (b *kerberosBackend) config(s logical.Storage) (*kerberosConfig, error) {
	raw, err := s.Get(configPath)
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

	return conf, nil
}

var backendHelp string = `
The Kerberos Auth Backend allows authentication via Kerberos SPNEGO.
`
