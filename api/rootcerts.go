package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CertConfig determines where LoadCACerts will load certificates from.
type CertConfig struct {
	// CAFile is a path to a PEM-encoded certificate file or bundle. Takes
	// precedence over CACertificate and CAPath.
	CAFile string

	// CACertificate is a PEM-encoded certificate or bundle. Takes precedence
	// over CAPath.
	CACertificate []byte

	// CAPath is a path to a directory populated with PEM-encoded certificates.
	CAPath string
}

// ConfigureTLS sets up the RootCAs on the provided tls.Config based on the CertConfig specified.
func ConfigureTLS(t *tls.Config, c *CertConfig) error {
	if t == nil {
		return nil
	}
	// Greedily load all possible CA sources into the pool.
	pool, err := LoadCACerts(c)
	if err != nil {
		return err
	}
	t.RootCAs = pool
	return nil
}

// LoadCACerts loads a CertPool from all available CA sources in CertConfig.
func LoadCACerts(c *CertConfig) (*x509.CertPool, error) {
	// Start with system CAs.
	pool, err := LoadSystemCAs()
	if err != nil {
		pool = x509.NewCertPool()
	}

	// Load from CAFile, if specified.
	if c.CAFile != "" {
		if err := AppendCAFile(pool, c.CAFile); err != nil {
			return nil, err
		}
	}

	// Load from CACertificate, if specified.
	if len(c.CACertificate) != 0 {
		if err := AppendCertificate(pool, c.CACertificate); err != nil {
			return nil, err
		}
	}

	// Load from CAPath, if specified.
	if c.CAPath != "" {
		if err := AppendCAPath(pool, c.CAPath); err != nil {
			return nil, err
		}
	}

	return pool, nil
}

// AppendCAFile loads a single PEM-encoded file and appends it to the provided CertPool.
func AppendCAFile(pool *x509.CertPool, caFile string) error {
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
func AppendCertificate(pool *x509.CertPool, ca []byte) error {
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return errors.New("Error appending CA: Couldn't parse PEM")
	}
	return nil
}

// AppendCAPath loads all certificates from the provided directory into the CertPool.
func AppendCAPath(pool *x509.CertPool, caPath string) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Error loading file from CAPath: %w", err)
		}

		ok := pool.AppendCertsFromPEM(pem)
		if !ok {
			return fmt.Errorf("Error loading CA Path: Couldn't parse PEM in: %s", path)
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
func LoadSystemCAs() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Error loading system CA certificates: %w", err)
	}
	return pool, nil
}
