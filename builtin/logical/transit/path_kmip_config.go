// Copyright (c) OpenBao contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const kmipConfigPath = "config/kmip"

func (b *backend) pathKmipConfig() *framework.Path {
	return &framework.Path{
		Pattern: kmipConfigPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
		},

		Fields: map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Enable KMIP.",
			},
			"listen_addr": {
				Type:        framework.TypeString,
				Default:     "0.0.0.0:5696",
				Description: "TCP address the KMIP server will listen on (host:port).",
			},
			"server_cert_perm": {
				Type:        framework.TypeString,
				Description: "PEM-encoded TLS certificate for the KMIP server.",
			},
			"server_key_pem": {
				Type:         framework.TypeString,
				Description:  "PEM-encoded private key for the KMIP server certificate.",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			"tls_ca_cert_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate used to verify client certificates.",
			},
			"require_client_cert": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Wether to require and verify client TLS certificate",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKmipConfigRead,
			},
		},

		HelpSynopsis:    pathKmipConfigHelpSyn,
		HelpDescription: pathKmipConfigHelpDesc,
	}
}

func (b *backend) pathKmipConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getKmipConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"enabled":             cfg.Enabled,
			"listen_addr":         cfg.ListenAddr,
			"server_cert_pem":     cfg.ServerCertPEM,
			"tls_ca_cert_pem":     cfg.TLSCACertPEM,
			"require_client_cert": cfg.RequireClientCert,
		},
	}, nil
}

const pathKmipConfigHelpSyn = `Configure the KMIP server for this transit mount`

const pathKmipConfigHelpDesc = `
This path configures the KMIP (Key Management Interoperability Protocol) server
that is embedded in this transit secrets engine mount. External KMIP clients
(databases, storage arrays, backup software) can connect to this server to
manage and use transit-managed cryptographic keys via the standard KMIP protocol.
`
