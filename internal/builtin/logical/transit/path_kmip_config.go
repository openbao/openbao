// Copyright (c) OpenBao contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/tls"

	"github.com/openbao/openbao/builtin/logical/transit/kmip"
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

	return &logical.Response{
		Data: map[string]interface{}{
			"enabled":             cfg.Enabled,
			"listen_addr":         cfg.ListenAddr,
			"server_cert_pem":     cfg.CertPem,
			"tls_ca_cert_pem":     cfg.TlsCaCertPem,
			"require_client_cert": cfg.RequireClientCert,
		},
	}, nil
}

func (b *backend) pathKmipConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getKmipConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	oldCfg := cfg

	if v, ok := d.GetOk("enabled"); ok {
		cfg.Enabled = v.(bool)
	}
	if v, ok := d.GetOk("listen_addr"); ok {
		cfg.ListenAddr = v.(string)
	}
	if v, ok := d.GetOk("server_cert_pem"); ok {
		cfg.CertPem = v.(string)
	}
	if v, ok := d.GetOk("server_key_pem"); ok {
		cfg.KeyPem = v.(string)
	}
	if v, ok := d.GetOk("tls_ca_cert_pem"); ok {
		cfg.TlsCaCertPem = v.(string)
	}
	if v, ok := d.GetOk("require_client_cert"); ok {
		cfg.RequireClientCert = v.(bool)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:5696"
	}

	if cfg.Enabled {
		if cfg.CertPem == "" || cfg.KeyPem == "" {
			return logical.ErrorResponse("server_cert_pem and server_key_pem are requiered when enabling KMIP"), logical.ErrInvalidRequest
		}
		if _, err := tls.X509KeyPair([]byte(cfg.CertPem), []byte(cfg.KeyPem)); err != nil {
			return logical.ErrorResponse("invalid server cert/key: %s", err), logical.ErrInvalidRequest
		}
		if cfg.RequireClientCert && cfg.TlsCaCertPem == "" {
			return logical.ErrorResponse("tls_ca_cert_pem is required when require_client_cert is true"), logical.ErrInvalidRequest
		}
	}

	entry, err := logical.StorageEntryJSON(kmip.ConfigStoragePath, &cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := b.restartKmipServer(cfg, req.Storage); err != nil {
		// Roll storage back to previous config if server restart fails
		rollback, _ := logical.StorageEntryJSON(kmip.ConfigStoragePath, &oldCfg)
		_ = req.Storage.Put(ctx, rollback)

		if rbErr := b.restartKmipServer(oldCfg, req.Storage); rbErr != nil {
			return logical.ErrorResponse("failed to restart KMIP server: %s; rollback also failed: %s", err, rbErr), nil
		}

		return logical.ErrorResponse("failed to restart KMIP server: %s", err), nil
	}

	return &logical.Response{}, nil
}

const pathKmipConfigHelpSyn = `Configure the KMIP server for this transit mount`

const pathKmipConfigHelpDesc = `
This path configures the KMIP (Key Management Interoperability Protocol) server
that is embedded in this transit secrets engine mount. External KMIP clients
(databases, storage arrays, backup software) can connect to this server to
manage and use transit-managed cryptographic keys via the standard KMIP protocol.
`
