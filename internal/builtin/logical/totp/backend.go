// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package totp

import (
	"context"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"zgo.at/zcache/v2"
)

const operationPrefixTOTP = "totp"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"key/",
			},
		},

		Paths: []*framework.Path{
			pathListKeys(&b),
			pathKeys(&b),
			pathCode(&b),
		},

		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	b.usedCodes = zcache.New[string, struct{}](0, 30*time.Second)

	return &b
}

type backend struct {
	*framework.Backend

	usedCodes *zcache.Cache[string, struct{}]
}

const backendHelp = `
The TOTP backend dynamically generates time-based one-time use passwords.
`
