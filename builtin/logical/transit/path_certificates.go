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
				Description: "Name of the key to sign the CSR with.",
			},
			"version": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: "Version of the key to use for signing. If the version is set to `latest`, or is not set, the current key will be returned",
			},
			"csr": {
				Type:        framework.TypeString,
				Required:    false,
				Description: "Optional PEM-encoded CSR template to use as the basis for the new CSR signed by this key. If not set, an empty CSR is used.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCreateCSRWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "get-csr",
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
				Description: "Name of the key to import the certificate chain against.",
			},
			"version": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: "Version of the key to import the certificate chain against.",
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
					OperationVerb: "set-chain",
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
		return logical.ErrorResponse("key with provided name '%s' not found", name), logical.ErrInvalidRequest
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
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	name := data.Get("name").(string)

	policy, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return logical.ErrorResponse("key with provided name '%s' not found", name), logical.ErrInvalidRequest
	}

	if !b.System().CachingDisabled() {
		policy.Lock(true)
	}
	defer policy.Unlock()

	// check if transit key supports signing
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

	// get certificate chain
	pemCertChain := data.Get("certificate_chain").(string)
	certChain, err := parseCertificateChain(pemCertChain)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	err = policy.PersistCertificateChain(ctx, req.Storage, keyVersion, certChain)
	if err != nil {
		prefixedErr := fmt.Errorf("failed to persist certificate chain: %w", err)
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(prefixedErr.Error()), logical.ErrInvalidRequest
		default:
			return nil, prefixedErr
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
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
	pathCreateCSRHelpSynopsis    = "Sign a CSR with a key in transit"
	pathCreateCSRHelpDescription = `
This path signs a CSR using the provided key, ensuring the key material stays
within Transit. If no CSR is provided, it signs an empty CSR. Otherwise, it signs
the provided CSR, replacing its key material with the key material.
The key in transit must be a signing key and not be derived.
`

	pathImportCertChainHelpSynopsis    = "Set a certificate chain for a key in transit"
	pathImportCertChainHelpDescription = `
This paths sets the certificate chain for the provided key, ensuring the key
material stays within Transit and certificates are managed in one place.
It also allows chain updates and rotation, as it will overwrite any existing
certificate chain.
`
)
