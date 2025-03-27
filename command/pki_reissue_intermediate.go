// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/posener/complete"
)

type PKIReIssueCACommand struct {
	*BaseCommand

	flagConfig          string
	flagReturnIndicator string
	flagDefaultDisabled bool
	flagList            bool

	flagKeyStorageSource string
	flagNewIssuerName    string
}

func (c *PKIReIssueCACommand) Synopsis() string {
	return "Uses a parent certificate and a template certificate to create a new issuer on a child mount"
}

func (c *PKIReIssueCACommand) Help() string {
	helpText := `
Usage: bao pki reissue PARENT TEMPLATE CHILD_MOUNT options
`
	return strings.TrimSpace(helpText)
}

func (c *PKIReIssueCACommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:       "type",
		Target:     &c.flagKeyStorageSource,
		Default:    "internal",
		EnvVar:     "",
		Usage:      `Options are “existing” - to use an existing key inside vault, “internal” - to generate a new key inside vault, or “kms” - to link to an external key.  Exported keys are not available through this API.`,
		Completion: complete.PredictSet("internal", "existing", "kms"),
	})

	f.StringVar(&StringVar{
		Name:    "issuer_name",
		Target:  &c.flagNewIssuerName,
		Default: "",
		EnvVar:  "",
		Usage:   `If present, the newly created issuer will be given this name`,
	})

	return set
}

func (c *PKIReIssueCACommand) Run(args []string) int {
	// Parse Args
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	args = f.Args()

	if len(args) < 3 {
		c.UI.Error("Not enough arguments: expected parent issuer and child-mount location and some key_value argument")
		return 1
	}

	stdin := (io.Reader)(os.Stdin)
	if c.flagNonInteractive {
		stdin = bytes.NewReader(nil)
	}

	userData, err := parseArgsData(stdin, args[3:])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to parse K=V data: %s", err))
		return 1
	}

	// Check We Have a Client
	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to obtain client: %v", err))
		return 1
	}

	parentIssuer := sanitizePath(args[0]) // /pki/issuer/default
	templateIssuer := sanitizePath(args[1])
	intermediateMount := sanitizePath(args[2])

	templateIssuerBundle, err := readIssuer(client, templateIssuer)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error fetching template certificate %v : %v", templateIssuer, err))
		return 1
	}
	certificate := templateIssuerBundle.certificate

	useExistingKey := c.flagKeyStorageSource == "existing"
	keyRef := ""
	if useExistingKey {
		keyRef = templateIssuerBundle.keyId

		if keyRef == "" {
			c.UI.Error(fmt.Sprintf("Template issuer %s did not have a key id field set in response which is required", templateIssuer))
			return 1
		}
	}

	templateData, err := parseTemplateCertificate(*certificate, useExistingKey, keyRef)
	data := updateTemplateWithData(templateData, userData)

	return pkiIssue(c.BaseCommand, parentIssuer, intermediateMount, c.flagNewIssuerName, c.flagKeyStorageSource, data)
}

func updateTemplateWithData(template map[string]interface{}, changes map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{}

	for key, value := range template {
		data[key] = value
	}

	// ttl and not_after set the same thing.  Delete template ttl if using not_after:
	if _, ok := changes["not_after"]; ok {
		delete(data, "ttl")
	}

	// If we are updating the key_type, do not set key_bits
	if _, ok := changes["key_type"]; ok && changes["key_type"] != template["key_type"] {
		delete(data, "key_bits")
	}

	for key, value := range changes {
		data[key] = value
	}

	return data
}

func parseTemplateCertificate(certificate x509.Certificate, useExistingKey bool, keyRef string) (templateData map[string]interface{}, err error) {
	// Generate Certificate Signing Parameters
	templateData = map[string]interface{}{
		"common_name": certificate.Subject.CommonName,
		"alt_names":   makeAltNamesCommaSeparatedString(certificate.DNSNames, certificate.EmailAddresses),
		"ip_sans":     makeIpAddressCommaSeparatedString(certificate.IPAddresses),
		"uri_sans":    makeUriCommaSeparatedString(certificate.URIs),
		// other_sans (string: "") - Specifies custom OID/UTF8-string SANs. These must match values specified on the role in allowed_other_sans (see role creation for allowed_other_sans globbing rules). The format is the same as OpenSSL: <oid>;<type>:<value> where the only current valid type is UTF8. This can be a comma-delimited list or a JSON string slice.
		// Punting on Other_SANs, shouldn't really be on CAs
		"signature_bits":        findSignatureBits(certificate.SignatureAlgorithm),
		"exclude_cn_from_sans":  determineExcludeCnFromSans(certificate),
		"ou":                    certificate.Subject.OrganizationalUnit,
		"organization":          certificate.Subject.Organization,
		"country":               certificate.Subject.Country,
		"locality":              certificate.Subject.Locality,
		"province":              certificate.Subject.Province,
		"street_address":        certificate.Subject.StreetAddress,
		"postal_code":           certificate.Subject.PostalCode,
		"serial_number":         certificate.Subject.SerialNumber,
		"ttl":                   (certificate.NotAfter.Sub(certificate.NotBefore)).String(),
		"max_path_length":       certificate.MaxPathLen,
		"permitted_dns_domains": strings.Join(certificate.PermittedDNSDomains, ","),
		"use_pss":               isPSS(certificate.SignatureAlgorithm),
	}

	if useExistingKey {
		templateData["skid"] = hex.EncodeToString(certificate.SubjectKeyId) // TODO: Double Check this with someone
		if keyRef == "" {
			return nil, errors.New("unable to create certificate template for existing key without a key_id")
		}
		templateData["key_ref"] = keyRef
	} else {
		templateData["key_type"] = getKeyType(certificate.PublicKeyAlgorithm.String())
		templateData["key_bits"] = findBitLength(certificate.PublicKey)
	}

	return templateData, nil
}

func isPSS(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.SHA256WithRSAPSS:
		return true
	default:
		return false
	}
}

func makeAltNamesCommaSeparatedString(names []string, emails []string) string {
	return strings.Join(names, ",") + "," + strings.Join(emails, ",")
}

func makeUriCommaSeparatedString(uris []*url.URL) string {
	stringAddresses := make([]string, len(uris))
	for i, uri := range uris {
		stringAddresses[i] = uri.String()
	}
	return strings.Join(stringAddresses, ",")
}

func makeIpAddressCommaSeparatedString(addresses []net.IP) string {
	stringAddresses := make([]string, len(addresses))
	for i, address := range addresses {
		stringAddresses[i] = address.String()
	}
	return strings.Join(stringAddresses, ",")
}

func determineExcludeCnFromSans(certificate x509.Certificate) bool {
	cn := certificate.Subject.CommonName
	if cn == "" {
		return false
	}

	emails := certificate.EmailAddresses
	for _, email := range emails {
		if email == cn {
			return false
		}
	}

	dnses := certificate.DNSNames
	for _, dns := range dnses {
		if dns == cn {
			return false
		}
	}

	return true
}

func findBitLength(publicKey any) int {
	if publicKey == nil {
		return 0
	}
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P224():
			return 224
		case elliptic.P256():
			return 256
		case elliptic.P384():
			return 384
		case elliptic.P521():
			return 521
		default:
			return 0
		}
	default:
		return 0
	}
}

func findSignatureBits(algo x509.SignatureAlgorithm) int {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return -1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return 256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return 384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return 512
	case x509.PureEd25519:
		return 0
	default:
		return -1
	}
}

func getKeyType(goKeyType string) string {
	switch goKeyType {
	case "RSA":
		return "rsa"
	case "ECDSA":
		return "ec"
	case "Ed25519":
		return "ed25519"
	default:
		return ""
	}
}
