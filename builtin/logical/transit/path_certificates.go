package transit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathCreateCSR() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/csr",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Name of the key to create a CSR for.",
			},
			"version": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: "The version of the key to create a CSR for. If not set, the latest version, `latest`, will be used.",
			},
			"csr": {
				Type:        framework.TypeString,
				Required:    false,
				Description: "PEM encoded CSR template to use. The information attributes will be used as a basis for the CSR with the key in transit. If not set, a default template will be used.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathCreateCSRWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
			},
		},
		HelpSynopsis:    pathCreateCSRHelpSynopsis,
		HelpDescription: pathCreateCSRHelpDescription,
	}
}

// func (b *backend) pathImportCertChain() *framework.Path {
// 	return nil
// }

func (b *backend) pathCreateCSRWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	policy, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return logical.ErrorResponse(fmt.Sprintf("key with provided name '%s' not found", name)), logical.ErrInvalidRequest
	}

	if !b.System().CachingDisabled() {
		policy.Lock(false)
	}
	defer policy.Unlock()

	// check if key supports signing
	if !policy.Type.SigningSupported() {
		return logical.ErrorResponse("key type '%s' does not support signing", policy.Type), logical.ErrInvalidRequest
	}

	// check if key can be derived
	if policy.Derived {
		return logical.ErrorResponse("operation not supported for keys with derivation enabled"), logical.ErrInvalidRequest
	}

	// transit key version
	signingKeyVersion := policy.LatestVersion
	version, versionSet := data.GetOk("version")
	if versionSet {
		signingKeyVersion = version.(int)
	}

	// read and parse CSR template
	pemCSRTemplate := data.Get("csr").(string)
	csrTemplate, err := parseCSR(pemCSRTemplate)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	csr, err := policy.CreateCSR(signingKeyVersion, csrTemplate)
	if err != nil {
		prefixedErr := fmt.Errorf("could not create the csr: %w", err)
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(prefixedErr.Error()), logical.ErrInvalidRequest
		default:
			return nil, prefixedErr
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name": policy.Name,
			"type": policy.Type.String(),
			"csr":  string(csr),
		},
	}, nil
}

func parseCSR(csrTemplate string) (*x509.CertificateRequest, error) {
	if csrTemplate == "" {
		return &x509.CertificateRequest{}, nil
	}
	csrBlock, _ := pem.Decode([]byte(csrTemplate))
	if csrBlock == nil {
		return nil, errors.New("could not decode PEM CSR")
	}
	return x509.ParseCertificateRequest(csrBlock.Bytes)
}

const (
	// NOTE: `from` or `for`?
	pathCreateCSRHelpSynopsis    = "Create a CSR for a key in transit."
	pathCreateCSRHelpDescription = "This path is used to create a CSR for a key in transit. If a CSR template is provided, its significant information, expect key related data, are included in the CSR otherwise an empty CSR is returned. The key in transit must be a signing key and not be derived. The CSR can be signed by the latest version of the key in transit or by a specific version of the key in transit. The custom template must a valid CSR and PEM encoded."

	pathImportCertChainHelpSynopsis    = ""
	pathImportCertChainHelpDescription = ""
)
