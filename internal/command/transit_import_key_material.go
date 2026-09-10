// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func readTransitImportKey(source, format string) ([]byte, error) {
	switch format {
	case "base64", "raw", "pem":
	default:
		return nil, errors.New("invalid key format: expected base64, raw, or pem")
	}
	if source == "" {
		return nil, errors.New("key material must not be empty")
	}
	fromFile := strings.HasPrefix(source, "@")
	if format != "base64" && !fromFile {
		return nil, errors.New("raw and PEM key formats require @path notation")
	}
	material := []byte(source)
	if fromFile {
		var err error
		material, err = os.ReadFile(source[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading key material file: %w", err)
		}
	}
	if len(material) == 0 {
		return nil, errors.New("key material must not be empty")
	}
	switch format {
	case "base64":
		key, err := base64.StdEncoding.DecodeString(string(material))
		if err != nil {
			return nil, fmt.Errorf("error base64 decoding source key material: %w", err)
		}
		if len(key) == 0 {
			return nil, errors.New("key material must not be empty")
		}
		return key, nil
	case "raw":
		return material, nil
	default:
		return parseTransitImportPEM(material)
	}
}

func parseTransitImportPEM(material []byte) ([]byte, error) {
	material = bytes.TrimSpace(material)
	// pem.Decode can skip leading text and malformed blocks. Accept exactly one
	// block instead, so that extra key material cannot be silently discarded.
	if !bytes.HasPrefix(material, []byte("-----BEGIN ")) || bytes.Count(material, []byte("-----BEGIN ")) != 1 {
		return nil, errors.New("expected exactly one private-key PEM block")
	}
	block, rest := pem.Decode(material)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one private-key PEM block")
	}
	if len(block.Headers) != 0 || block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("encrypted PEM and PEM headers are not supported")
	}

	// Some x509 parsers accept trailing DER data. Check the complete object
	// before parsing so that normalization cannot discard extra material.
	var object asn1.RawValue
	rest, err := asn1.Unmarshal(block.Bytes, &object)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid private-key DER in PEM block")
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported PEM block: expected PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY")
	}
	if err != nil {
		return nil, errors.New("invalid private key in PEM block")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("unable to encode private key as PKCS#8 DER")
	}
	return der, nil
}
