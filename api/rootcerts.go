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

// certConfig determines where loadCACerts will load certificates from.
type certConfig struct {
	// CAFile is a path to a PEM-encoded certificate file or bundle.
	CAFile string

	// CACertificate is a PEM-encoded certificate or bundle.
	CACertificate []byte

	// CAPath is a path to a directory populated with PEM-encoded certificates.
	CAPath string

	// SkipSystemCerts determines if system certificates should be included in the pool.
	// Defaults to false
	SkipSystemCerts bool
}

// configureTLS sets up the RootCAs on the provided tls.Config based on the certConfig specified.
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

// loadCACerts loads a CertPool from all available CA sources in certConfig.
func loadCACerts(c *certConfig) (*x509.CertPool, error) {
	// to track if we've successfully added any certificates
	var added bool
	var certPool *x509.CertPool

	// If SkipSystemCerts is set to false, load system CAs
	if !c.SkipSystemCerts {
		pool, err := loadSystemCAs()

		if err != nil {
			certPool = x509.NewCertPool()
		} else {
			certPool = pool
		}
	} else {
		certPool = x509.NewCertPool()
	}

	// Load from CAFile, if specified.
	if c.CAFile != "" {
		fileAdded, err := appendCAFile(certPool, c.CAFile)
		if err != nil {
			return nil, err
		}
		added = added || fileAdded
	}

	// Load from CACertificate, if specified.
	if len(c.CACertificate) != 0 {
		fileAdded, err := appendCertificate(certPool, c.CACertificate)
		if err != nil {
			return nil, err
		}
		added = added || fileAdded
	}

	// Load from CAPath, if specified.
	if c.CAPath != "" {
		fileAdded, err := appendCAPath(certPool, c.CAPath)
		if err != nil {
			return nil, err
		}
		added = added || fileAdded
	}

	// If no certificates were added and system CAs failed, return nil.
	if !added {
		return nil, nil
	}

	return certPool, nil
}

// appendCAFile loads a single PEM-encoded file and appends it to the provided CertPool.
func appendCAFile(pool *x509.CertPool, caFile string) (bool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return false, fmt.Errorf("Error loading CA File: %w", err)
	}

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return false, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", caFile)
	}

	return true, nil
}

// appendCertificate appends an in-memory PEM-encoded certificate or bundle to the provided CertPool.
func appendCertificate(pool *x509.CertPool, ca []byte) (bool, error) {
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return false, errors.New("Error appending CA: Couldn't parse PEM")
	}
	return true, nil
}

// appendCAPath loads and appends all valid PEM-encoded certificates from the specified directory
// to the provided CertPool. Non-certificate PEM blocks are ignored.
func appendCAPath(pool *x509.CertPool, caPath string) (bool, error) {
	var added bool
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

		// Decode and process all PEM blocks opportunistically
		for len(pemData) > 0 {
			var block *pem.Block
			block, pemData = pem.Decode(pemData)
			if block == nil {
				break
			}
			certificates, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				// Not a valid certificate, ignore it and move on
				continue
			}

			for _, cert := range certificates {
				pool.AddCert(cert)
				added = true
			}
		}

		return nil
	}

	err := filepath.Walk(caPath, walkFn)
	if err != nil {
		return false, err
	}

	return added, nil
}

// loadSystemCAs loads the system's CA certificates into a pool.
func loadSystemCAs() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Error loading system CA certificates: %w", err)
	}
	return pool, nil
}
