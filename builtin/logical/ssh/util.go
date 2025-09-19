// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"
)

const (
	issuerRefParam = "issuer_ref"
)

var (
	nameMatcher          = regexp.MustCompile("^" + framework.GenericNameRegex(issuerRefParam) + "$")
	errIssuerNameInUse   = errutil.UserError{Err: "issuer name already in use"}
	errIssuerNameIsEmpty = errutil.UserError{Err: "expected non-empty issuer name"}
)

// Takes an IP address and role name and checks if the IP is part
// of CIDR blocks belonging to the role.
func roleContainsIP(ctx context.Context, s logical.Storage, roleName string, ip string) (bool, error) {
	if roleName == "" {
		return false, errors.New("missing role name")
	}

	if ip == "" {
		return false, errors.New("missing ip")
	}

	roleEntry, err := s.Get(ctx, fmt.Sprintf("roles/%s", roleName))
	if err != nil {
		return false, fmt.Errorf("error retrieving role %w", err)
	}
	if roleEntry == nil {
		return false, fmt.Errorf("role %q not found", roleName)
	}

	var role sshRole
	if err := roleEntry.DecodeJSON(&role); err != nil {
		return false, fmt.Errorf("error decoding role %q", roleName)
	}

	if matched, err := cidrListContainsIP(ip, role.CIDRList); err != nil {
		return false, err
	} else {
		return matched, nil
	}
}

// Returns true if the IP supplied by the user is part of the comma
// separated CIDR blocks
func cidrListContainsIP(ip, cidrList string) (bool, error) {
	if len(cidrList) == 0 {
		return false, errors.New("IP does not belong to role")
	}
	for _, item := range strings.Split(cidrList, ",") {
		_, cidrIPNet, err := net.ParseCIDR(item)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR entry %q", item)
		}
		if cidrIPNet.Contains(net.ParseIP(ip)) {
			return true, nil
		}
	}
	return false, nil
}

func parsePublicSSHKey(key string) (ssh.PublicKey, error) {
	keyParts := strings.Split(key, " ")
	if len(keyParts) > 1 {
		// Someone has sent the 'full' public key rather than just the base64 encoded part that the ssh library wants
		key = keyParts[1]
	}

	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey([]byte(decodedKey))
}

func convertMapToStringValue(initial map[string]interface{}) map[string]string {
	result := map[string]string{}
	for key, value := range initial {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func convertMapToIntSlice(initial map[string]interface{}) (map[string][]int, error) {
	var err error
	result := map[string][]int{}

	for key, value := range initial {
		result[key], err = parseutil.SafeParseIntSlice(value, 0 /* no upper bound on number of keys lengths per key type */)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Serve a template processor for custom format inputs
func substQuery(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}

	return tpl
}

// handleKeyGeneration parses the input parameters and returns the public
// and private keys  by either generating them or using the provided ones.
func (b *backend) handleKeyGeneration(data *framework.FieldData) (publicKey string, privateKey string, generateSigningKey bool, err error) {
	publicKey = data.Get("public_key").(string)
	privateKey = data.Get("private_key").(string)

	generateSigningKeyRaw, ok := data.GetOk("generate_signing_key")
	switch {
	// generation of signing key is explicitly set to true
	case ok && generateSigningKeyRaw.(bool):
		if publicKey != "" || privateKey != "" {
			err = errutil.UserError{Err: "public_key and private_key must not be set when generate_signing_key is set to true"}
			return
		}
		generateSigningKey = true
	// generation of signing key explicitly set to false, or not set and we have both a public and private key
	case publicKey != "" && privateKey != "":
		_, err = parsePublicSSHKey(publicKey)
		if err != nil {
			err = errutil.UserError{Err: fmt.Sprintf("could not parse public_key provided value: %v", err)}
			return
		}

		_, err = ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			err = errutil.UserError{Err: fmt.Sprintf("could not parse private_key provided value: %v", err)}
			return
		}
	// generation of signing key not set and no key material provided so generate
	case publicKey == "" && privateKey == "" && !ok:
		generateSigningKey = true
	// generation of signing key set as false but not key material provided
	case publicKey == "" && privateKey == "" && ok && !generateSigningKeyRaw.(bool):
		err = errutil.UserError{Err: "missing public_key"}
		return
	// generation of signing key not set and only one key material provided
	default:
		err = errutil.UserError{Err: "only one of public_key and private_key set; both must be set to use, or both must be blank to auto-generate"}
		return
	}

	if generateSigningKey {
		keyType := data.Get("key_type").(string)
		keyBits := data.Get("key_bits").(int)

		publicKey, privateKey, err = generateSSHKeyPair(b.Backend.GetRandomReader(), keyType, keyBits)
		if err != nil {
			err = errutil.InternalError{Err: err.Error()}
			return
		}
	}

	if publicKey == "" || privateKey == "" {
		err = errutil.InternalError{Err: "failed to generate or parse the keys"}
	}

	return
}

func getIssuerRef(data *framework.FieldData) string {
	return extractRef(data, issuerRefParam)
}

func getDefaultRef(data *framework.FieldData) string {
	return extractRef(data, defaultRef)
}

func extractRef(data *framework.FieldData, paramName string) string {
	value := strings.TrimSpace(data.Get(paramName).(string))
	if strings.EqualFold(value, defaultRef) {
		return defaultRef
	}
	return value
}

func getIssuerName(sc *storageContext, data *framework.FieldData) (string, error) {
	issuerName := ""
	issuerNameIface, ok := data.GetOk("issuer_name")
	if ok {
		issuerName = strings.TrimSpace(issuerNameIface.(string))
		if len(issuerName) == 0 {
			return issuerName, errIssuerNameIsEmpty
		}
		if strings.ToLower(issuerName) == defaultRef {
			return issuerName, errutil.UserError{Err: "reserved keyword 'default' can not be used as issuer name"}
		}
		if !nameMatcher.MatchString(issuerName) {
			return issuerName, errutil.UserError{Err: "issuer name contained invalid characters"}
		}
		issuerId, err := sc.resolveIssuerReference(issuerName)
		if err == nil {
			return issuerName, errIssuerNameInUse
		}

		if issuerId != IssuerRefNotFound {
			return issuerName, errutil.InternalError{Err: err.Error()}
		}
	}

	return issuerName, nil
}

// handleStorageContextErr is a small helper function to automatically return
// internal failed operations as errors, 500 status codes, and users errors
// as responses, with 400 status code. It can optionally include an additional
// message log as a prefix to the error message while preserving the original error type.
func handleStorageContextErr(err error, additionalMessageLog ...string) (*logical.Response, error) {
	if err == nil {
		return nil, nil
	}

	if len(additionalMessageLog) > 0 && additionalMessageLog[0] != "" {
		err = fmt.Errorf("%s: %w", additionalMessageLog[0], err)
	}

	switch err.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(err.Error()), nil
	case errutil.InternalError:
		return nil, errutil.InternalError{Err: err.Error()}
	default:
		return nil, fmt.Errorf("%w", err)
	}
}
