// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/helper/consts"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathListCertsRevoked(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/revoked/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationSuffix: "revoked-certs",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListRevokedCertsHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: `List of Keys`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathListRevokedHelpSyn,
		HelpDescription: pathListRevokedHelpDesc,
	}
}

func pathRevoke(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `revoke`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "revoke",
		},

		Fields: map[string]*framework.FieldSchema{
			"serial_number": {
				Type: framework.TypeString,
				Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
			},
			"certificate": {
				Type: framework.TypeString,
				Description: `Certificate to revoke in PEM format; must be
signed by an issuer in this mount.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.metricsWrap("revoke", noRole, b.pathRevokeWrite),
				// This should never be forwarded. See backend.go for more information.
				// If this needs to write, the entire request will be forwarded to the
				// active node of the current performance cluster, but we don't want to
				// forward invalid revoke requests there.
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"revocation_time": {
								Type:        framework.TypeInt64,
								Description: `Revocation Time`,
								Required:    false,
							},
							"revocation_time_rfc3339": {
								Type:        framework.TypeTime,
								Description: `Revocation Time`,
								Required:    false,
							},
							"state": {
								Type:        framework.TypeString,
								Description: `Revocation State`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func pathRevokeWithKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `revoke-with-key`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "revoke",
			OperationSuffix: "with-key",
		},

		Fields: map[string]*framework.FieldSchema{
			"serial_number": {
				Type: framework.TypeString,
				Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
			},
			"certificate": {
				Type: framework.TypeString,
				Description: `Certificate to revoke in PEM format; must be
signed by an issuer in this mount.`,
			},
			"private_key": {
				Type: framework.TypeString,
				Description: `Key to use to verify revocation permission; must
be in PEM format.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.metricsWrap("revoke", noRole, b.pathRevokeWrite),
				// This should never be forwarded. See backend.go for more information.
				// If this needs to write, the entire request will be forwarded to the
				// active node of the current performance cluster, but we don't want to
				// forward invalid revoke requests there.
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"revocation_time": {
								Type:        framework.TypeInt64,
								Description: `Revocation Time`,
								Required:    false,
							},
							"revocation_time_rfc3339": {
								Type:        framework.TypeTime,
								Description: `Revocation Time`,
								Required:    false,
							},
							"state": {
								Type:        framework.TypeString,
								Description: `Revocation State`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func pathRotateCRL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `crl/rotate`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "rotate",
			OperationSuffix: "crl",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRotateCRLRead,
				// See backend.go; we will read a lot of data prior to calling write,
				// so this request should be forwarded when it is first seen, not
				// when it is ready to write.
				ForwardPerformanceStandby: true,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"success": {
								Type:        framework.TypeBool,
								Description: `Whether rotation was successful`,
								Required:    true,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathRotateCRLHelpSyn,
		HelpDescription: pathRotateCRLHelpDesc,
	}
}

func pathRotateDeltaCRL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `crl/rotate-delta`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "rotate",
			OperationSuffix: "delta-crl",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRotateDeltaCRLRead,
				// See backend.go; we will read a lot of data prior to calling write,
				// so this request should be forwarded when it is first seen, not
				// when it is ready to write.
				ForwardPerformanceStandby: true,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"success": {
								Type:        framework.TypeBool,
								Description: `Whether rotation was successful`,
								Required:    true,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathRotateDeltaCRLHelpSyn,
		HelpDescription: pathRotateDeltaCRLHelpDesc,
	}
}

func (b *backend) pathRevokeWriteHandleCertificate(ctx context.Context, req *logical.Request, certPem string) (string, bool, *x509.Certificate, error) {
	// This function handles just the verification of the certificate against
	// the global issuer set, checking whether or not it is importable.
	//
	// We return the parsed serial number, an optionally-nil byte array to
	// write out to disk, and an error if one occurred.
	if b.useLegacyBundleCaStorage() {
		// We require listing all issuers from the 1.11 method. If we're
		// still using the legacy CA bundle but with the newer certificate
		// attribute, we err and require the operator to upgrade and migrate
		// prior to servicing new requests.
		return "", false, nil, errutil.UserError{Err: "unable to process BYOC revocation until CA issuer migration has completed"}
	}

	// First start by parsing the certificate.
	if len(certPem) < 75 {
		// See note in pathImportIssuers about this check.
		return "", false, nil, errutil.UserError{Err: "provided certificate data was too short; perhaps a path was passed to the API rather than the contents of a PEM file"}
	}

	pemBlock, _ := pem.Decode([]byte(certPem))
	if pemBlock == nil {
		return "", false, nil, errutil.UserError{Err: "certificate contains no PEM data"}
	}

	certReference, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return "", false, nil, errutil.UserError{Err: fmt.Sprintf("certificate could not be parsed: %v", err)}
	}

	// Ensure we have a well-formed serial number before continuing.
	serial := serialFromCert(certReference)
	if len(serial) == 0 {
		return "", false, nil, errutil.UserError{Err: "invalid serial number on presented certificate"}
	}

	// We have two approaches here: we could start verifying against issuers
	// (which involves fetching and parsing them), or we could see if, by
	// some chance we've already imported it (cheap). The latter tells us
	// if we happen to have a serial number collision (which shouldn't
	// happen in practice) versus an already-imported cert (which might
	// happen and its fine to handle safely).
	//
	// Start with the latter since its cheaper. Fetch the cert (by serial)
	// and if it exists, compare the contents.
	sc := b.makeStorageContext(ctx, req.Storage)
	certEntry, err := fetchCertBySerial(sc, "certs/", serial)
	if err != nil {
		return serial, false, nil, err
	}

	if certEntry != nil {
		// As seen with importing issuers, it is best to parse the certificate
		// and compare parsed values, rather than attempting to infer equality
		// from the raw data.
		certReferenceStored, err := x509.ParseCertificate(certEntry.Value)
		if err != nil {
			return serial, false, nil, err
		}

		if !areCertificatesEqual(certReference, certReferenceStored) {
			// Here we refuse the import with an error because the two certs
			// are unequal but we would've otherwise overwritten the existing
			// copy.
			return serial, false, nil, errors.New("certificate with same serial but unequal value already present in this cluster's storage; refusing to revoke")
		} else {
			// Otherwise, we can return without an error as we've already
			// imported this certificate, likely when we issued it. We don't
			// need to re-verify the signature as we assume it was already
			// verified when it was imported.
			return serial, false, certReferenceStored, nil
		}
	}

	// Otherwise, we must not have a stored copy. From here on out, the second
	// parameter (except in error cases) should cause the cert to write out.
	//
	// Fetch and iterate through each issuer.
	issuers, err := sc.listIssuers()
	if err != nil {
		return serial, false, nil, err
	}

	foundMatchingIssuer := false
	for _, issuerId := range issuers {
		issuer, err := sc.fetchIssuerById(issuerId)
		if err != nil {
			return serial, false, nil, err
		}

		issuerCert, err := issuer.GetCertificate()
		if err != nil {
			return serial, false, nil, err
		}

		if err := certReference.CheckSignatureFrom(issuerCert); err == nil {
			// If the signature was valid, we found our match and can safely
			// exit.
			foundMatchingIssuer = true
			break
		}
	}

	if foundMatchingIssuer {
		return serial, true, certReference, nil
	}

	return serial, false, nil, errutil.UserError{Err: "unable to verify signature on presented cert from any present issuer in this mount; certificates from previous CAs will need to have their issuing CA and key re-imported if revocation is necessary"}
}

func (b *backend) pathRevokeWriteHandleKey(req *logical.Request, certReference *x509.Certificate, keyPem string) error {
	if keyPem == "" {
		// The only way to get here should be via the /revoke endpoint;
		// validate the path one more time and return an error if necessary.
		if req.Path != "revoke" {
			return errors.New("must have private key to revoke via the /revoke-with-key path")
		}

		// Otherwise, we don't need to validate the key and thus can return
		// with success.
		return nil
	}

	// Now parse the key's PEM block.
	pemBlock, _ := pem.Decode([]byte(keyPem))
	if pemBlock == nil {
		return errutil.UserError{Err: "provided key PEM block contained no data or failed to parse"}
	}

	// Parse the inner DER key.
	signer, _, err := certutil.ParseDERKey(pemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse provided private key: %w", err)
	}

	return validatePrivateKeyMatchesCert(signer, certReference)
}

func validatePrivateKeyMatchesCert(signer crypto.Signer, certReference *x509.Certificate) error {
	public := signer.Public()

	switch certReference.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPriv, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return errutil.UserError{Err: "provided private key type does not match certificate's public key type"}
		}

		if err := rsaPriv.Validate(); err != nil {
			return errutil.UserError{Err: fmt.Sprintf("error validating integrity of private key: %v", err)}
		}
	}

	return validatePublicKeyMatchesCert(public, certReference)
}

func validatePublicKeyMatchesCert(verifier crypto.PublicKey, certReference *x509.Certificate) error {
	// Finally, verify if the cert and key match. This code has been
	// cribbed from the Go TLS config code, with minor modifications.
	//
	// In particular, we validate against the derived public key
	// components and ensure we validate exponent and curve information
	// as well.
	//
	// See: https://github.com/golang/go/blob/c6a2dada0df8c2d75cf3ae599d7caed77d416fa2/src/crypto/tls/tls.go#L304-L331
	switch certPub := certReference.PublicKey.(type) {
	case *rsa.PublicKey:
		privPub, ok := verifier.(*rsa.PublicKey)
		if !ok {
			return errutil.UserError{Err: "provided private key type does not match certificate's public key type"}
		}
		if certPub.N.Cmp(privPub.N) != 0 || certPub.E != privPub.E {
			return errutil.UserError{Err: "provided private key does not match certificate's public key"}
		}
	case *ecdsa.PublicKey:
		privPub, ok := verifier.(*ecdsa.PublicKey)
		if !ok {
			return errutil.UserError{Err: "provided private key type does not match certificate's public key type"}
		}
		if certPub.X.Cmp(privPub.X) != 0 || certPub.Y.Cmp(privPub.Y) != 0 || certPub.Params().Name != privPub.Params().Name {
			return errutil.UserError{Err: "provided private key does not match certificate's public key"}
		}
	case ed25519.PublicKey:
		privPub, ok := verifier.(ed25519.PublicKey)
		if !ok {
			return errutil.UserError{Err: "provided private key type does not match certificate's public key type"}
		}
		if subtle.ConstantTimeCompare(privPub, certPub) == 0 {
			return errutil.UserError{Err: "provided private key does not match certificate's public key"}
		}
	default:
		return errutil.UserError{Err: "certificate has an unknown public key algorithm; unable to validate provided private key; ask an admin to revoke this certificate instead"}
	}

	return nil
}

func (b *backend) pathRevokeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData, _ *roleEntry) (*logical.Response, error) {
	rawSerial, haveSerial := data.GetOk("serial_number")
	rawCertificate, haveCert := data.GetOk("certificate")
	sc := b.makeStorageContext(ctx, req.Storage)

	if !haveSerial && !haveCert {
		return logical.ErrorResponse("The serial number or certificate to revoke must be provided."), nil
	} else if haveSerial && haveCert {
		return logical.ErrorResponse("Must provide either the certificate or the serial to revoke; not both."), nil
	}

	var keyPem string
	if req.Path == "revoke-with-key" {
		rawKey, haveKey := data.GetOk("private_key")
		if !haveKey {
			return logical.ErrorResponse("Must have private key to revoke via the /revoke-with-key path."), nil
		}

		keyPem = rawKey.(string)
		if len(keyPem) < 64 {
			// See note in pathImportKeyHandler...
			return logical.ErrorResponse("Provided data for private_key was too short; perhaps a path was passed to the API rather than the contents of a PEM file?"), nil
		}
	}

	writeCert := false
	var cert *x509.Certificate
	var serial string

	config, err := sc.Backend.crlBuilder.getConfigWithUpdate(sc)
	if err != nil {
		return nil, fmt.Errorf("error revoking serial: %s: failed reading config: %w", serial, err)
	}

	if haveCert {
		serial, writeCert, cert, err = b.pathRevokeWriteHandleCertificate(ctx, req, rawCertificate.(string))
		if err != nil {
			return nil, err
		}
	} else {
		// Easy case: this cert should be in storage already.
		serial = rawSerial.(string)
		if len(serial) == 0 {
			return logical.ErrorResponse("The serial number must be provided"), nil
		}

		certEntry, err := fetchCertBySerial(sc, "certs/", serial)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(err.Error()), nil
			default:
				return nil, err
			}
		}

		if certEntry != nil {
			cert, err = x509.ParseCertificate(certEntry.Value)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate: %w", err)
			}
		}
	}

	if cert == nil {
		return logical.ErrorResponse("certificate with serial %s not found.", serial), nil
	}

	// Before we write the certificate, we've gotta verify the request in
	// the event of a PoP-based revocation scheme; we don't want to litter
	// storage with issued-but-not-revoked certificates.
	if err := b.pathRevokeWriteHandleKey(req, cert, keyPem); err != nil {
		return nil, err
	}

	// At this point, a forward operation will occur if we're on a standby
	// node as we're now attempting to write the bytes of the cert out to
	// disk.
	if writeCert {
		err := req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   "certs/" + normalizeSerial(serial),
			Value: cert.Raw,
		})
		if err != nil {
			return nil, err
		}
	}

	// Assumption: this check is cheap. Call this twice, in the cert-import
	// case, to allow cert verification to get rejected on the standby node,
	// but we still need it to protect the serial number case.
	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	b.revokeStorageLock.Lock()
	defer b.revokeStorageLock.Unlock()

	return revokeCert(sc, config, cert)
}

func (b *backend) pathRotateCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.revokeStorageLock.RLock()
	defer b.revokeStorageLock.RUnlock()

	sc := b.makeStorageContext(ctx, req.Storage)
	warnings, crlErr := b.crlBuilder.rebuild(sc, false)
	if crlErr != nil {
		switch crlErr.(type) {
		case errutil.UserError:
			return logical.ErrorResponse("Error during CRL building: %s", crlErr), nil
		default:
			return nil, fmt.Errorf("error encountered during CRL building: %w", crlErr)
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"success": true,
		},
	}

	for index, warning := range warnings {
		resp.AddWarning(fmt.Sprintf("Warning %d during CRL rebuild: %v", index+1, warning))
	}

	return resp, nil
}

func (b *backend) pathRotateDeltaCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	cfg, err := b.crlBuilder.getConfigWithUpdate(sc)
	if err != nil {
		return nil, fmt.Errorf("error fetching CRL configuration: %w", err)
	}

	isEnabled := cfg.EnableDelta

	warnings, crlErr := b.crlBuilder.rebuildDeltaCRLsIfForced(sc, true)
	if crlErr != nil {
		switch crlErr.(type) {
		case errutil.UserError:
			return logical.ErrorResponse("Error during delta CRL building: %s", crlErr), nil
		default:
			return nil, fmt.Errorf("error encountered during delta CRL building: %w", crlErr)
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"success": true,
		},
	}

	if !isEnabled {
		resp.AddWarning("requested rebuild of delta CRL when delta CRL is not enabled; this is a no-op")
	}
	for index, warning := range warnings {
		resp.AddWarning(fmt.Sprintf("Warning %d during CRL rebuild: %v", index+1, warning))
	}

	return resp, nil
}

func (b *backend) pathListRevokedCertsHandler(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, request.Storage)

	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	revokedCerts, err := sc.listRevokedCertsPage(after, limit)
	if err != nil {
		return nil, err
	}

	// Normalize serial back to a format people are expecting.
	for i, serial := range revokedCerts {
		revokedCerts[i] = denormalizeSerial(serial)
	}

	return logical.ListResponse(revokedCerts), nil
}

const pathRevokeHelpSyn = `
Revoke a certificate by serial number or with explicit certificate.

When calling /revoke-with-key, the private key corresponding to the
certificate must be provided to authenticate the request.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoke. A root token or corresponding
private key is required.
`

const pathRotateCRLHelpSyn = `
Force a rebuild of the CRL.
`

const pathRotateCRLHelpDesc = `
Force a rebuild of the CRL. This can be used to remove expired certificates from it if no certificates have been revoked. A root token is required.
`

const pathRotateDeltaCRLHelpSyn = `
Force a rebuild of the delta CRL.
`

const pathRotateDeltaCRLHelpDesc = `
Force a rebuild of the delta CRL. This can be used to force an update of the otherwise periodically-rebuilt delta CRLs.
`

const pathListRevokedHelpSyn = `
List all revoked serial numbers within the local cluster
`

const pathListRevokedHelpDesc = `
Returns a list of serial numbers for revoked certificates in the local cluster.
`
