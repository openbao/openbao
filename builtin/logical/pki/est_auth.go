package pki

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type estAuthMethod int

const (
	estAuthNone estAuthMethod = iota
	estAuthToken
	estAuthTLSClientCert
	estAuthHTTPBasic
)

type estAuthInfo struct {
	Method        estAuthMethod
	Token         string
	ClientCerts   []*x509.Certificate
	BasicAuthUser string
	BasicAuthPass string
}

func (b *backend) validateEstAuthentication(ctx context.Context, req *logical.Request, config *estConfigEntry) (*logical.Auth, error) {
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("EST is not enabled")
	}

	// By the time we get here, an upstream handler should have already performed
	// authentication (e.g., via client cert or basic auth) and injected a
	// token into the request. We just need to ensure a token is present.
	if req.ClientToken == "" {
		return nil, fmt.Errorf("authentication required: no credentials provided")
	}

	return nil, nil
}

func (b *backend) requireEstAuthentication(ctx context.Context, req *logical.Request, data *framework.FieldData) (*estConfigEntry, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	// Get EST configuration
	config, err := sc.getEstConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get EST config: %w", err)
	}

	if !config.Enabled {
		return nil, fmt.Errorf("EST is not enabled")
	}

	// Validate authentication
	_, err = b.validateEstAuthentication(ctx, req, config)
	if err != nil {
		return config, err
	}

	return config, nil
}
