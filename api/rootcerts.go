// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// See https://github.com/hashicorp/go-rootcerts's rootcerts.go as of bb0b55efd5a1de16cb10686096b9596cfbab1fad.

package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CertConfig determines where LoadCACerts will load certificates from.
type certConfig struct {
	// CAFile is a path to a PEM-encoded certificate file or bundle.
	CAFile string

	// CACertificate is a PEM-encoded certificate or bundle.
	CACertificate []byte

	// CAPath is a path to a directory populated with PEM-encoded certificates.
	CAPath string
}

// ConfigureTLS sets up the RootCAs on the provided tls.Config based on the CertConfig specified.
func configureTLS(t *tls.Config, c *certConfig) error {
	if t == nil {
		return nil
	}

	// Greedily load all possible CA sources into the pool.
	pool, err := loadCACerts(c)
	if err != nil {
		return err
	}
	t.RootCAs = pool
	return nil
}

// LoadCACerts loads a CertPool from all available CA sources in CertConfig.
func loadCACerts(c *certConfig) (*x509.CertPool, error) {
	// Start with system CAs.
	pool, err := loadSystemCAs()
	if err != nil {
		pool = x509.NewCertPool()
	}

	// Load from CAFile, if specified.
	if c.CAFile != "" {
		if err := appendCAFile(pool, c.CAFile); err != nil {
			return nil, err
		}
	}

	// Load from CACertificate, if specified.
	if len(c.CACertificate) != 0 {
		if err := appendCertificate(pool, c.CACertificate); err != nil {
			return nil, err
		}
	}

	// Load from CAPath, if specified.
	if c.CAPath != "" {
		if err := appendCAPath(pool, c.CAPath); err != nil {
			return nil, err
		}
	}

	return pool, nil
}

// AppendCAFile loads a single PEM-encoded file and appends it to the provided CertPool.
func appendCAFile(pool *x509.CertPool, caFile string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("Error loading CA File: %w", err)
	}

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", caFile)
	}

	return nil
}

// AppendCertificate appends an in-memory PEM-encoded certificate or bundle to the provided CertPool.
func appendCertificate(pool *x509.CertPool, ca []byte) error {
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return errors.New("Error appending CA: Couldn't parse PEM")
	}
	return nil
}

func appendCAPath(pool *x509.CertPool, caPath string) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		pemData, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Error loading file from CAPath: %w", err)
		}

		// Decode the PEM blocks and only append certificate blocks
		var block *pem.Block
		rest := pemData
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			// Ensure the PEM block is a certificate
			if block.Type != "CERTIFICATE" {
				fmt.Printf("Ignoring non-certificate PEM block found in %s\n", path)
				continue
			}

			// Append the certificate to the pool
			ok := pool.AppendCertsFromPEM(pem.EncodeToMemory(block))
			if !ok {
				return fmt.Errorf("Error loading CA Path: Couldn't parse PEM in %s", path)
			}
		}

		return nil
	}

	err := filepath.Walk(caPath, walkFn)
	if err != nil {
		return err
	}

	return nil
}

// LoadSystemCAs loads the system's CA certificates into a pool.
func loadSystemCAs() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Error loading system CA certificates: %w", err)
	}
	return pool, nil
}
