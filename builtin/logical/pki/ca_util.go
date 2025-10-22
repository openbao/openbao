// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getGenerationParams(sc *storageContext, data *framework.FieldData) (exported bool, format string, role *roleEntry, errorResp *logical.Response) {
	exportedStr := data.Get("exported").(string)
	switch exportedStr {
	case "exported":
		exported = true
	case "internal":
	case "existing":
	case "kms":
	default:
		errorResp = logical.ErrorResponse(
			`the "exported" path parameter must be "internal", "existing", exported" or "kms"`)
		return exported, format, role, errorResp
	}

	format = getFormat(data)
	if format == "" {
		errorResp = logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`)
		return exported, format, role, errorResp
	}

	keyType, keyBits, err := sc.getKeyTypeAndBitsForRole(data)
	if err != nil {
		errorResp = logical.ErrorResponse(err.Error())
		return exported, format, role, errorResp
	}

	role = &roleEntry{
		TTL:                       time.Duration(data.Get("ttl").(int)) * time.Second,
		KeyType:                   keyType,
		KeyBits:                   keyBits,
		SignatureBits:             data.Get("signature_bits").(int),
		UsePSS:                    data.Get("use_pss").(bool),
		AllowLocalhost:            true,
		AllowAnyName:              true,
		AllowIPSANs:               true,
		AllowWildcardCertificates: new(bool),
		EnforceHostnames:          false,
		AllowedURISANs:            []string{"*"},
		AllowedOtherSANs:          []string{"*"},
		AllowedSerialNumbers:      []string{"*"},
		AllowedUserIDs:            []string{"*"},
		OU:                        data.Get("ou").([]string),
		Organization:              data.Get("organization").([]string),
		Country:                   data.Get("country").([]string),
		Locality:                  data.Get("locality").([]string),
		Province:                  data.Get("province").([]string),
		StreetAddress:             data.Get("street_address").([]string),
		PostalCode:                data.Get("postal_code").([]string),
		NotBeforeDuration:         time.Duration(data.Get("not_before_duration").(int)) * time.Second,
		CNValidations:             []string{"disabled"},
	}
	*role.AllowWildcardCertificates = true

	if role.KeyBits, role.SignatureBits, err = certutil.ValidateDefaultOrValueKeyTypeSignatureLength(role.KeyType, role.KeyBits, role.SignatureBits); err != nil {
		errorResp = logical.ErrorResponse(err.Error())
	}

	return exported, format, role, errorResp
}

func generateCABundle(sc *storageContext, input *inputBundle, data *certutil.CreationBundle, randomSource io.Reader) (*certutil.ParsedCertBundle, error) {
	if existingKeyRequested(input) {
		keyRef, err := getKeyRefWithErr(input.apiData)
		if err != nil {
			return nil, err
		}

		keyEntry, err := sc.getExistingKeyFromRef(keyRef)
		if err != nil {
			return nil, err
		}

		return certutil.CreateCertificateWithKeyGenerator(data, randomSource, existingKeyGeneratorFromBytes(keyEntry))
	}

	return certutil.CreateCertificateWithRandomSource(data, randomSource)
}

func generateCSRBundle(sc *storageContext, input *inputBundle, data *certutil.CreationBundle, addBasicConstraints bool, randomSource io.Reader) (*certutil.ParsedCSRBundle, error) {
	if existingKeyRequested(input) {
		keyRef, err := getKeyRefWithErr(input.apiData)
		if err != nil {
			return nil, err
		}

		key, err := sc.getExistingKeyFromRef(keyRef)
		if err != nil {
			return nil, err
		}

		return certutil.CreateCSRWithKeyGenerator(data, addBasicConstraints, randomSource, existingKeyGeneratorFromBytes(key))
	}

	return certutil.CreateCSRWithRandomSource(data, addBasicConstraints, randomSource)
}

func (sc *storageContext) getKeyTypeAndBitsForRole(data *framework.FieldData) (string, int, error) {
	exportedStr := data.Get("exported").(string)
	var keyType string
	var keyBits int

	switch exportedStr {
	case "internal":
		fallthrough
	case "exported":
		keyType = data.Get("key_type").(string)
		keyBits = data.Get("key_bits").(int)
		return keyType, keyBits, nil
	}

	// existing and kms types don't support providing the key_type and key_bits args.
	_, okKeyType := data.Raw["key_type"]
	_, okKeyBits := data.Raw["key_bits"]

	if okKeyType || okKeyBits {
		return "", 0, errors.New("invalid parameter for the kms/existing path parameter, key_type nor key_bits arguments can be set in this mode")
	}

	var pubKey crypto.PublicKey
	if existingKeyRequestedFromFieldData(data) {
		existingPubKey, err := sc.getExistingPublicKey(data)
		if err != nil {
			return "", 0, errors.New("failed to lookup public key from existing key: " + err.Error())
		}
		pubKey = existingPubKey
	}

	privateKeyType, keyBits, err := getKeyTypeAndBitsFromPublicKeyForRole(pubKey)
	return string(privateKeyType), keyBits, err
}

func (sc *storageContext) getExistingPublicKey(data *framework.FieldData) (crypto.PublicKey, error) {
	keyRef, err := getKeyRefWithErr(data)
	if err != nil {
		return nil, err
	}
	id, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		return nil, err
	}
	key, err := sc.fetchKeyById(id)
	if err != nil {
		return nil, err
	}
	return getPublicKey(key)
}

func getKeyTypeAndBitsFromPublicKeyForRole(pubKey crypto.PublicKey) (certutil.PrivateKeyType, int, error) {
	var keyType certutil.PrivateKeyType
	var keyBits int

	switch pubKey.(type) {
	case *rsa.PublicKey:
		keyType = certutil.RSAPrivateKey
		keyBits = certutil.GetPublicKeySize(pubKey)
	case *ecdsa.PublicKey:
		keyType = certutil.ECPrivateKey
	case ed25519.PublicKey:
		keyType = certutil.Ed25519PrivateKey
	default:
		return certutil.UnknownPrivateKey, 0, fmt.Errorf("unsupported public key: %#v", pubKey)
	}
	return keyType, keyBits, nil
}

func (sc *storageContext) getExistingKeyFromRef(keyRef string) (*keyEntry, error) {
	keyId, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		return nil, err
	}
	return sc.fetchKeyById(keyId)
}

func existingKeyGeneratorFromBytes(key *keyEntry) certutil.KeyGenerator {
	return func(_ string, _ int, container certutil.ParsedPrivateKeyContainer, _ io.Reader) error {
		signer, _, pemBytes, err := getSignerFromKeyEntryBytes(key)
		if err != nil {
			return err
		}

		container.SetParsedPrivateKey(signer, key.PrivateKeyType, pemBytes.Bytes)
		return nil
	}
}

func buildSignVerbatimRoleWithNoData(role *roleEntry) *roleEntry {
	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: addSignVerbatimRoleFields(map[string]*framework.FieldSchema{}),
	}
	return buildSignVerbatimRole(data, role)
}

func buildSignVerbatimRole(data *framework.FieldData, role *roleEntry) *roleEntry {
	entry := &roleEntry{
		AllowLocalhost:            true,
		AllowAnyName:              true,
		AllowIPSANs:               true,
		AllowWildcardCertificates: new(bool),
		EnforceHostnames:          false,
		KeyType:                   "any",
		UseCSRCommonName:          true,
		UseCSRSANs:                true,
		AllowedOtherSANs:          []string{"*"},
		AllowedSerialNumbers:      []string{"*"},
		AllowedURISANs:            []string{"*"},
		AllowedUserIDs:            []string{"*"},
		CNValidations:             []string{"disabled"},
		GenerateLease:             new(bool),
		// If adding new fields to be read, update the field list within addSignVerbatimRoleFields
		KeyUsage:                      data.Get("key_usage").([]string),
		ExtKeyUsage:                   data.Get("ext_key_usage").([]string),
		ExtKeyUsageOIDs:               data.Get("ext_key_usage_oids").([]string),
		SignatureBits:                 data.Get("signature_bits").(int),
		UsePSS:                        data.Get("use_pss").(bool),
		BasicConstraintsValidForNonCA: data.Get("basic_constraints_valid_for_non_ca").(bool),
	}
	*entry.AllowWildcardCertificates = true
	*entry.GenerateLease = false

	if role != nil {
		if role.TTL > 0 {
			entry.TTL = role.TTL
		}
		if role.MaxTTL > 0 {
			entry.MaxTTL = role.MaxTTL
		}
		if role.GenerateLease != nil {
			*entry.GenerateLease = *role.GenerateLease
		}
		if role.NotBeforeDuration > 0 {
			entry.NotBeforeDuration = role.NotBeforeDuration
		}
		entry.NoStore = role.NoStore
		entry.Issuer = role.Issuer
		if _, ok := data.GetOk("basic_constraints_valid_for_non_ca"); !ok {
			entry.BasicConstraintsValidForNonCA = role.BasicConstraintsValidForNonCA
		}
	}

	if len(entry.Issuer) == 0 {
		entry.Issuer = defaultRef
	}

	return entry
}
