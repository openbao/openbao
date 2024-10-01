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
	pool, err := LoadCACerts(c)
	if err != nil {
		return err
	}
	t.RootCAs = pool
	return nil
}

// LoadCACerts loads a CertPool based on the CertConfig specified.
func LoadCACerts(c *CertConfig) (*x509.CertPool, error) {
	if c == nil {
		c = &CertConfig{}
	}
	if c.CAFile != "" {
		return LoadCAFile(c.CAFile)
	}
	if len(c.CACertificate) != 0 {
		return AppendCertificate(c.CACertificate)
	}
	if c.CAPath != "" {
		return LoadCAPath(c.CAPath)
	}

	return LoadSystemCAs()
}

// LoadCAFile loads a single PEM-encoded file from the path specified.
func LoadCAFile(caFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA File: %w", err)
	}

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", caFile)
	}

	return pool, nil
}

// AppendCertificate appends an in-memory PEM-encoded certificate or bundle and returns a pool.
func AppendCertificate(ca []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return nil, errors.New("Error appending CA: Couldn't parse PEM")
	}

	return pool, nil
}

// LoadCAPath walks the provided path and loads all certificates encountered into a pool.
func LoadCAPath(caPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
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
		return nil, err
	}

	return pool, nil
}

// LoadSystemCAs loads the system's CA certificates into a pool.
func LoadSystemCAs() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Error loading system CA certificates: %w", err)
	}
	return pool, nil
}
