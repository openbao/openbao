// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathEstCaCerts wires the unauthenticated EST /cacerts endpoint.
func pathEstCaCerts(b *backend) []*framework.Path {
	return buildEstFrameworkPaths(b, patternEstCaCerts, "/cacerts")
}

func patternEstCaCerts(b *backend, pattern string) *framework.Path {
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
			OperationVerb:   "est-ca-certs",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathEstCaCertsRead},
		},
		HelpSynopsis:    "EST cacerts endpoint - returns CA certificate chain",
		HelpDescription: "This endpoint returns the CA certificate chain in PKCS#7 format, base64 encoded per RFC 7030.",
	}
}

func (b *backend) pathEstCaCertsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	// Check if EST is enabled
	config, err := sc.getEstConfig()
	if err != nil {
		return nil, err
	}

	if !config.Enabled {
		return logical.ErrorResponse("EST is not enabled"), logical.ErrUnsupportedPath
	}

	// Determine which issuer to use based on label, role, or default
	pathPolicy, err := resolveEstPathPolicyForCacerts(config, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	issuerName, err := b.issuerRefForPathPolicy(ctx, req, pathPolicy)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if issuerName == "" {
		issuerName = defaultRef
	}

	// Get the issuer
	issuer, err := sc.resolveIssuerReference(issuerName)
	if err != nil {
		return nil, err
	}

	// Load the certificate
	issuerEntry, bundle, err := sc.fetchCertBundleByIssuerId(issuer, false)
	if err != nil {
		return nil, fmt.Errorf("error fetching issuer certificate: %w", err)
	}

	if issuerEntry == nil || bundle == nil || bundle.Certificate == "" {
		return nil, fmt.Errorf("unable to fetch issuer certificate")
	}

	// Build certificate chain from the bundle
	certs, err := buildCAChain(bundle.Certificate, bundle.CAChain)
	if err != nil {
		return nil, fmt.Errorf("error building CA chain: %w", err)
	}

	// Create PKCS#7 structure containing the CA chain
	pkcs7Data, err := createPKCS7CertsOnly(certs)
	if err != nil {
		return nil, fmt.Errorf("error creating PKCS#7 structure: %w", err)
	}

	// Per RFC 7030 Section 4.1.3, EST responses must be base64-encoded
	// when Content-Transfer-Encoding is set to base64
	base64Data := base64.StdEncoding.EncodeToString(pkcs7Data)

	resp := &logical.Response{
		Data: map[string]interface{}{
			"http_status_code":               200,
			"http_content_type":              estPKCS7ContentType,
			"http_content_transfer_encoding": "base64",
			"http_raw_body":                  []byte(base64Data), // Base64-encoded PKCS#7
		},
	}

	return resp, nil
}

func resolveEstPathPolicyForCacerts(config *estConfigEntry, data *framework.FieldData) (string, error) {
	if data != nil {
		if labelRaw, ok := data.GetOk("label"); ok {
			labelName := labelRaw.(string)
			if labelName != "" {
				policy, exists := config.LabelToPathPolicy[labelName]
				if !exists {
					return "", fmt.Errorf("EST label not found: %s", labelName)
				}
				return policy, nil
			}
		}
		if roleRaw, ok := data.GetOk("role"); ok {
			roleName := roleRaw.(string)
			if roleName != "" {
				return fmt.Sprintf("role:%s", roleName), nil
			}
		}
	}

	return config.DefaultPathPolicy, nil
}

func (b *backend) issuerRefForPathPolicy(ctx context.Context, req *logical.Request, policy string) (string, error) {
	policy = strings.TrimSpace(policy)
	if policy == "" || policy == "sign-verbatim" {
		return defaultRef, nil
	}

	if strings.HasPrefix(policy, "role:") {
		roleName := strings.TrimSpace(policy[len("role:"):])
		if roleName == "" {
			return "", fmt.Errorf("path policy role cannot be empty")
		}
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			return "", fmt.Errorf("failed to load role %s: %w", roleName, err)
		}
		if role == nil {
			return "", fmt.Errorf("role not found: %s", roleName)
		}
		issuerRef := role.Issuer
		if issuerRef == "" {
			issuerRef = defaultRef
		}
		return issuerRef, nil
	}

	return "", fmt.Errorf("invalid path policy: %s", policy)
}
