// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathEstSimpleReenroll wires the authenticated EST /simplereenroll endpoint.
func pathEstSimpleReenroll(b *backend) []*framework.Path {
	return buildEstFrameworkPaths(b, patternEstSimpleReenroll, "/simplereenroll")
}

func patternEstSimpleReenroll(b *backend, pattern string) *framework.Path {
	fields := map[string]*framework.FieldSchema{}

	if strings.Contains(pattern, "roles/") {
		fields["role"] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "The desired role to use for EST operations",
			Required:    true,
		}
	}

	if strings.Contains(pattern, ".well-known/est/") && strings.Count(pattern, "/") > 2 {
		fields["label"] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "The EST label for routing to specific configuration",
			Required:    true,
		}
	}

	return &framework.Path{
		Pattern: pattern,
		Fields:  fields,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "est-simple-reenroll",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathEstSimpleReenrollWrite,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "EST simplereenroll endpoint - renews an existing certificate",
		HelpDescription: "This endpoint accepts a PKCS#10 CSR in PKCS#7 format (base64 encoded) for certificate renewal per RFC 7030.",
	}
}

func (b *backend) pathEstSimpleReenrollWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleEstSimpleEnroll(ctx, req, data, estSimpleEnrollOptions{
		requireTLSClientCert:             true,
		enforceCSRMatchesTLSCertIdentity: true,
	})
}
