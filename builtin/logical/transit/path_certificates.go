package transit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

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
			logical.UpdateOperation: &framework.PathOperation{
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

func (b *backend) pathImportCertChain() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/set-certificate",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Name of the key.",
			},
			"version": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: "Key version of which the certificate chain is going to be attatched to. If not set, the latest version, `latest`, will be used.",
			},
			"certificate_chain": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "PEM encoded certificate chain. It should be composed by one or more concatenated PEM blocks and ordered starting from the end-entity certificate.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathImportCertChainWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
			},
		},
		HelpSynopsis:    pathImportCertChainHelpSynopsis,
		HelpDescription: pathImportCertChainHelpDescription,
	}
}

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
	keyVersion := policy.LatestVersion
	version, versionSet := data.GetOk("version")
	if versionSet {
		keyVersion = version.(int)
	}

	// read and parse CSR template
	pemCSRTemplate := data.Get("csr").(string)
	csrTemplate, err := parseCSR(pemCSRTemplate)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	csr, err := policy.CreateCSR(keyVersion, csrTemplate)
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

func (b *backend) pathImportCertChainWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
		policy.Lock(true) // NOTE: Lock as we might write to the policy
	}
	defer policy.Unlock()

	// check if transit key supports signing
	if !policy.Type.SigningSupported() {
		return logical.ErrorResponse(fmt.Sprintf("key type '%s' does not support signing", policy.Type)), logical.ErrInvalidRequest
	}

	// check if key can be derived
	if policy.Derived {
		return logical.ErrorResponse("operation not supported for keys with derivation enabled"), logical.ErrInvalidRequest
	}

	// transit key version
	keyVersion := policy.LatestVersion
	version, versionSet := data.GetOk("version")
	if versionSet {
		keyVersion = version.(int)
	}

	// get certificate chain
	pemCertChain := data.Get("certificate_chain").(string)
	certChain, err := parseCertificateChain(pemCertChain)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	err = policy.ValidateAndPersistCertificateChain(ctx, req.Storage, keyVersion, certChain)
	if err != nil {
		prefixedErr := fmt.Errorf("failed to persist certificate chain: %w", err)
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(prefixedErr.Error()), logical.ErrInvalidRequest
		default:
			return nil, prefixedErr
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":              policy.Name,
			"type":              policy.Type.String(),
			"certificate_chain": pemCertChain,
		},
	}, nil
}

func parseCertificateChain(certChain string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	var pemCertBlocks []*pem.Block
	pemBytes := []byte(strings.TrimSpace(certChain))
	for len(pemBytes) > 0 {
		var pemCertBlock *pem.Block
		pemCertBlock, pemBytes = pem.Decode(pemBytes)
		if pemCertBlock == nil {
			return nil, errors.New("could not decode a PEM block in the certificate chain")
		}

		switch pemCertBlock.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
			pemCertBlocks = append(pemCertBlocks, pemCertBlock)
		default:
			// Ignore other PEM blocks
		}
	}

	if len(pemCertBlocks) == 0 {
		return nil, errors.New("provided certificate chain did not contain any valid PEM encoded certificate")
	}

	for _, pemCertBlock := range pemCertBlocks {
		certificate, err := x509.ParseCertificate(pemCertBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse a certificate in the certificate chain: %w", err)
		}
		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

const (
	pathCreateCSRHelpSynopsis    = "Create a CSR for a key in transit."
	pathCreateCSRHelpDescription = "This path is used to create a CSR for a key in transit. If a CSR template is provided, its significant information, expect key related data, are included in the CSR otherwise an empty CSR is returned. The key in transit must be a signing key and not be derived. The CSR can be signed by the latest version of the key in transit or by a specific version of the key in transit. The custom template must a valid CSR and PEM encoded."

	pathImportCertChainHelpSynopsis    = "Imports an externally-signed certificate chain into an existing key version"
	pathImportCertChainHelpDescription = "This path is used to import an externally-signed certificate chain into an existing key version in transit. The leaf certificate key has to match the selected key."
)
