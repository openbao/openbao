// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// Connection represents the connection information for a request. This
// is present on the Request structure for credential backends.
type Connection struct {
	// RemoteAddr is the network address that sent the request.
	RemoteAddr string `json:"remote_addr"`

	// RemotePort is the network port that sent the request.
	RemotePort int `json:"remote_port"`

	// ConnState is the TLS connection state if applicable.
	ConnState *tls.ConnectionState `sentinel:""`

	// ProxiedCertificate is a certificate verified by a proxy header.
	ProxiedCertificates    []*x509.Certificate `json:"-"`
	ProxiedCertificatesRaw [][]byte            `json:"proxied_certificates"`

	// PeerCertificate is a certificate verified by this server through a TLS
	// connection.
	PeerCertificates    []*x509.Certificate `json:"-"`
	PeerCertificatesRaw [][]byte            `json:"peer_certificates"`
}

func (c *Connection) GetPreferredCerts() ([]*x509.Certificate, error) {
	if c == nil {
		return nil, nil
	}

	if err := c.populateCerts(); err != nil {
		return nil, fmt.Errorf("while getting preferred certificate chain: %w", err)
	}

	if len(c.ProxiedCertificates) > 0 {
		return c.ProxiedCertificates, nil
	}

	return c.PeerCertificates, nil
}

func (c *Connection) populateCerts() error {
	if c == nil {
		return nil
	}

	// If we have a connection state but no peer certificates, push it into
	// peer certificates. This only occurs during testing.
	if c.ConnState != nil && len(c.PeerCertificates) == 0 && len(c.PeerCertificatesRaw) == 0 {
		c.PeerCertificates = c.ConnState.PeerCertificates
	}

	// Populate our raw certificates so forwarding works.
	c.populateRawCerts()

	// Populate parsed forms of our certificates if present.
	if err := c.populateParsedCerts(); err != nil {
		return err
	}

	return nil
}

func (c *Connection) populateRawCerts() {
	if len(c.ProxiedCertificates) > 0 && len(c.ProxiedCertificatesRaw) == 0 {
		c.ProxiedCertificatesRaw = make([][]byte, len(c.ProxiedCertificates))
		for i, cert := range c.ProxiedCertificates {
			c.ProxiedCertificatesRaw[i] = cert.Raw
		}
	}

	if len(c.PeerCertificates) > 0 && len(c.PeerCertificatesRaw) == 0 {
		c.PeerCertificatesRaw = make([][]byte, len(c.PeerCertificates))
		for i, cert := range c.PeerCertificates {
			c.PeerCertificatesRaw[i] = cert.Raw
		}
	}
}

func (c *Connection) populateParsedCerts() error {
	if len(c.ProxiedCertificatesRaw) > 0 && len(c.ProxiedCertificates) == 0 {
		c.ProxiedCertificates = make([]*x509.Certificate, len(c.ProxiedCertificatesRaw))
		for i, rawCert := range c.ProxiedCertificatesRaw {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("[cert %d]: failed to parse: %w", i, err)
			}

			c.ProxiedCertificates[i] = cert
		}
	}

	if len(c.PeerCertificatesRaw) > 0 && len(c.PeerCertificates) == 0 {
		c.PeerCertificates = make([]*x509.Certificate, len(c.PeerCertificatesRaw))
		for i, rawCert := range c.PeerCertificatesRaw {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("[cert %d]: failed to parse: %w", i, err)
			}

			c.PeerCertificates[i] = cert
		}
	}

	return nil
}
