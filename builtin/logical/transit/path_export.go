// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	exportTypeEncryptionKey    = "encryption-key"
	exportTypeSigningKey       = "signing-key"
	exportTypeHMACKey          = "hmac-key"
	exportTypePublicKey        = "public-key"
	exportTypeCertificateChain = "certificate-chain"
)

const (
	formatTypeDefault = ""
	formatTypeRaw     = "raw"
	formatTypeDer     = "der"
	formatTypePem     = "pem"
)

func (b *backend) pathExportKeys() *framework.Path {
	return &framework.Path{
		Pattern: "export/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("version"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "export",
			OperationSuffix: "key|key-version",
		},

		Fields: map[string]*framework.FieldSchema{
			"type": {
				Type:        framework.TypeString,
				Description: "Type of key to export (encryption-key, signing-key, hmac-key, public-key)",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"version": {
				Type:        framework.TypeString,
				Description: "Version of the key",
			},
			"format": {
				Type:        framework.TypeString,
				Description: "Format to export the key in: `` for the default format dependent on the key type; `raw` for the raw key value in base64 (applicable to symmetric keys and ed25519); `der` for a base64 encoded PKIX (SubjectPublicKeyInfo or PKCS8/PrivateKeyInfo) format (applicable to asymmetric keys); or `pem` for a PEM-encoded PKIX format (applicable to asymmetric keys).",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathPolicyExportRead,
			},
		},

		HelpSynopsis:    pathExportHelpSyn,
		HelpDescription: pathExportHelpDesc,
	}
}

func (b *backend) pathPolicyExportRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	exportType := d.Get("type").(string)
	name := d.Get("name").(string)
	version := d.Get("version").(string)
	format := d.Get("format").(string)

	switch exportType {
	case exportTypeEncryptionKey:
	case exportTypeSigningKey:
	case exportTypeHMACKey:
	case exportTypePublicKey:
	case exportTypeCertificateChain:
	default:
		return logical.ErrorResponse("invalid export type: %s", exportType), logical.ErrInvalidRequest
	}

	switch format {
	case formatTypeDefault:
	case formatTypeRaw:
	case formatTypeDer:
	case formatTypePem:
	default:
		return logical.ErrorResponse("invalid format: %s", format), logical.ErrInvalidRequest
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if !p.Exportable && exportType != exportTypePublicKey && exportType != exportTypeCertificateChain {
		return logical.ErrorResponse("private key material is not exportable"), nil
	}

	if p.SoftDeleted {
		return nil, fmt.Errorf("%v", keysutil.ErrSoftDeleted)
	}

	switch exportType {
	case exportTypeEncryptionKey:
		if !p.Type.EncryptionSupported() {
			return logical.ErrorResponse("encryption not supported for the key"), logical.ErrInvalidRequest
		}
	case exportTypeSigningKey:
		if !p.Type.SigningSupported() {
			return logical.ErrorResponse("signing not supported for the key"), logical.ErrInvalidRequest
		}
	case exportTypeCertificateChain:
		if !p.Type.SigningSupported() {
			return logical.ErrorResponse("certificate chain not supported for keys that do not support signing"), logical.ErrInvalidRequest
		}
	}

	retKeys := map[string]string{}
	switch version {
	case "":
		for k, v := range p.Keys {
			exportKey, err := getExportKey(p, &v, exportType, format)
			if err != nil {
				return nil, err
			}
			retKeys[k] = exportKey
		}

	default:
		var versionValue int
		if version == "latest" {
			versionValue = p.LatestVersion
		} else {
			version = strings.TrimPrefix(version, "v")
			versionValue, err = strconv.Atoi(version)
			if err != nil {
				return logical.ErrorResponse("invalid key version"), logical.ErrInvalidRequest
			}
		}

		if versionValue < p.MinDecryptionVersion {
			return logical.ErrorResponse("version for export is below minimum decryption version"), logical.ErrInvalidRequest
		}
		key, ok := p.Keys[strconv.Itoa(versionValue)]
		if !ok {
			return logical.ErrorResponse("version does not exist or cannot be found"), logical.ErrInvalidRequest
		}

		exportKey, err := getExportKey(p, &key, exportType, format)
		if err != nil {
			return nil, err
		}

		retKeys[strconv.Itoa(versionValue)] = exportKey
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name": p.Name,
			"type": p.Type.String(),
			"keys": retKeys,
		},
	}

	return resp, nil
}

func getExportKey(policy *keysutil.Policy, key *keysutil.KeyEntry, exportType string, format string) (string, error) {
	if policy == nil {
		return "", errors.New("nil policy provided")
	}

	switch exportType {
	case exportTypeHMACKey:
		src := key.HMACKey
		if policy.Type == keysutil.KeyType_HMAC {
			src = key.Key
		}
		if format == "der" || format == "pem" {
			return "", errors.New("unknown format for HMAC key; supported values are `` or `raw`")
		}

		return strings.TrimSpace(base64.StdEncoding.EncodeToString(src)), nil
	case exportTypeEncryptionKey:
		switch policy.Type {
		case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96, keysutil.KeyType_ChaCha20_Poly1305, keysutil.KeyType_XChaCha20_Poly1305:
			if format == "der" || format == "pem" {
				return "", errors.New("unknown format for HMAC key; supported values are `` or `raw`")
			}

			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil
		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			rsaKey, err := encodeRSAPrivateKey(key, format)
			if err != nil {
				return "", err
			}
			return rsaKey, nil
		}
	case exportTypeSigningKey:
		switch policy.Type {
		case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
			var curve elliptic.Curve
			switch policy.Type {
			case keysutil.KeyType_ECDSA_P384:
				curve = elliptic.P384()
			case keysutil.KeyType_ECDSA_P521:
				curve = elliptic.P521()
			default:
				curve = elliptic.P256()
			}

			ecKey, err := keyEntryToECPrivateKey(key, curve, format)
			if err != nil {
				return "", err
			}
			return ecKey, nil
		case keysutil.KeyType_ED25519:
			if len(key.Key) == 0 {
				return "", nil
			}

			return encodeED25519PrivateKey(key, format)
		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			rsaKey, err := encodeRSAPrivateKey(key, format)
			if err != nil {
				return "", err
			}
			return rsaKey, nil
		}
	case exportTypePublicKey:
		switch policy.Type {
		case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
			var curve elliptic.Curve
			switch policy.Type {
			case keysutil.KeyType_ECDSA_P384:
				curve = elliptic.P384()
			case keysutil.KeyType_ECDSA_P521:
				curve = elliptic.P521()
			default:
				curve = elliptic.P256()
			}

			ecKey, err := keyEntryToECPublicKey(key, curve, format)
			if err != nil {
				return "", err
			}
			return ecKey, nil
		case keysutil.KeyType_ED25519:
			return encodeED25519PublicKey(key, format)
		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			rsaKey, err := encodeRSAPublicKey(key, format)
			if err != nil {
				return "", err
			}
			return rsaKey, nil
		}
	case exportTypeCertificateChain:
		if key.CertificateChain == nil {
			return "", errors.New("selected key version does not have a certificate chain imported")
		}
		var pemCertificates []string
		for _, derCertificateBytes := range key.CertificateChain {
			pemCert := strings.TrimSpace(string(pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: derCertificateBytes,
				})))
			pemCertificates = append(pemCertificates, pemCert)
		}
		certificateChain := strings.Join(pemCertificates, "\n")
		return certificateChain, nil
	}

	return "", fmt.Errorf("unknown key type %v for export type %v", policy.Type, exportType)
}

func encodeRSAPrivateKey(key *keysutil.KeyEntry, format string) (string, error) {
	if format == "raw" {
		return "", errors.New("unknown key format for rsa key; supported values are ``, `der`, or `pem`")
	}

	if key == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	if key.IsPrivateKeyMissing() {
		return "", nil
	}

	var derBytes []byte
	var blockType string
	var err error
	if format == "" {
		derBytes = x509.MarshalPKCS1PrivateKey(key.RSAKey)
		blockType = "RSA PRIVATE KEY"
	} else if format == "der" || format == "pem" {
		derBytes, err = x509.MarshalPKCS8PrivateKey(key.RSAKey)
		blockType = "PRIVATE KEY"
	}
	if err != nil {
		return "", err
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(&pemBlock)
	return string(pemBytes), nil
}

func encodeRSAPublicKey(key *keysutil.KeyEntry, format string) (string, error) {
	if format == "raw" {
		return "", errors.New("unknown key format for rsa key; supported values are ``, `der`, or `pem`")
	}

	if key == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	var publicKey crypto.PublicKey
	publicKey = key.RSAPublicKey
	if key.RSAKey != nil {
		// Prefer the private key if it exists
		publicKey = key.RSAKey.Public()
	}

	if publicKey == nil {
		return "", errors.New("requested to encode an RSA public key with no RSA key present")
	}

	// Encode the RSA public key in PEM format to return over the API
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("error marshaling RSA public key: %w", err)
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if len(pemBytes) == 0 {
		return "", errors.New("failed to PEM-encode RSA public key")
	}

	return string(pemBytes), nil
}

func keyEntryToECPrivateKey(k *keysutil.KeyEntry, curve elliptic.Curve, format string) (string, error) {
	if format == "raw" {
		return "", errors.New("unknown key format for ec key; supported values are ``, `der`, or `pem`")
	}

	if k == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	if k.IsPrivateKeyMissing() {
		return "", nil
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     k.EC_X,
		Y:     k.EC_Y,
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         k.EC_D,
	}

	var blockType string
	var derBytes []byte
	var err error
	if format == "" {
		derBytes, err = x509.MarshalECPrivateKey(privKey)
		blockType = "EC PRIVATE KEY"
	} else if format == "der" || format == "pem" {
		derBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
		blockType = "PRIVATE KEY"
	}
	if err != nil {
		return "", err
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	return strings.TrimSpace(string(pem.EncodeToMemory(&pemBlock))), nil
}

func keyEntryToECPublicKey(k *keysutil.KeyEntry, curve elliptic.Curve, format string) (string, error) {
	if format == "raw" {
		return "", errors.New("unknown key format for ec key; supported values are ``, `der`, or `pem`")
	}

	if k == nil {
		return "", errors.New("nil KeyEntry provided")
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     k.EC_X,
		Y:     k.EC_Y,
	}

	blockType := "PUBLIC KEY"
	derBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return "", err
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	return strings.TrimSpace(string(pem.EncodeToMemory(&pemBlock))), nil
}

func encodeED25519PrivateKey(k *keysutil.KeyEntry, format string) (string, error) {
	if format == "" || format == "raw" {
		return base64.StdEncoding.EncodeToString(k.Key), nil
	}

	privKey := ed25519.PrivateKey(k.Key)

	blockType := "PRIVATE KEY"
	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", err
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	return strings.TrimSpace(string(pem.EncodeToMemory(&pemBlock))), nil
}

func encodeED25519PublicKey(k *keysutil.KeyEntry, format string) (string, error) {
	pubStr := strings.TrimSpace(k.FormattedPublicKey)
	if format == "" || format == "raw" {
		return pubStr, nil
	}

	pubRaw, err := base64.StdEncoding.DecodeString(pubStr)
	if err != nil {
		return "", err
	}

	pubKey := ed25519.PublicKey(pubRaw)

	blockType := "PUBLIC KEY"
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	if format == "der" {
		return base64.StdEncoding.EncodeToString(derBytes), nil
	}

	pemBlock := pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	return strings.TrimSpace(string(pem.EncodeToMemory(&pemBlock))), nil
}

const pathExportHelpSyn = `Export named encryption or signing key`

const pathExportHelpDesc = `
This path is used to export the named keys that are configured as
exportable.
`
