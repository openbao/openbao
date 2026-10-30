// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package dbtlsutil converts database plugin configuration fields into an
// in-memory TLS configuration. Keeping certificate material in memory avoids
// requiring operators to mount per-database secrets into the OpenBao process.
//
// The supported fields are:
//
//	tls_ca           PEM CA bundle used to verify the server
//	tls_certificate  PEM client certificate for mutual TLS
//	tls_key          PEM client private key for mutual TLS
//	tls_server_name  server name to verify instead of the connection host
//	tls_skip_verify  skip server certificate verification (testing only)
//	use_tls          enable TLS even when no other TLS field is set
//
// Older field names (ca_cert, client_cert, client_key, insecure) are accepted
// as aliases; when both are set, the current name wins. ca_path and
// tls_ca_path read the CA bundle from a file on the OpenBao server and are
// deprecated in favor of tls_ca.
package dbtlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/go-viper/mapstructure/v2"
)

// Config is the common inline TLS surface accepted by database plugins.
type Config struct {
	CA          string
	Certificate string
	Key         string
	ServerName  string
	SkipVerify  bool
	UseTLS      bool

	// CAPath is a CA bundle file on the OpenBao server.
	//
	// Deprecated: use CA (tls_ca) instead.
	CAPath string
}

// rawConfig holds both the current field names and their older aliases.
type rawConfig struct {
	CA           string `mapstructure:"tls_ca"`
	LegacyCA     string `mapstructure:"ca_cert"`
	Certificate  string `mapstructure:"tls_certificate"`
	LegacyCert   string `mapstructure:"client_cert"`
	Key          string `mapstructure:"tls_key"`
	LegacyKey    string `mapstructure:"client_key"`
	ServerName   string `mapstructure:"tls_server_name"`
	SkipVerify   *bool  `mapstructure:"tls_skip_verify"`
	LegacySkip   *bool  `mapstructure:"insecure"`
	UseTLS       bool   `mapstructure:"use_tls"`
	CAPath       string `mapstructure:"tls_ca_path"`
	LegacyCAPath string `mapstructure:"ca_path"`
}

// Decode reads the common TLS fields from a database plugin configuration.
func Decode(raw map[string]any) (Config, error) {
	var r rawConfig
	if err := mapstructure.WeakDecode(raw, &r); err != nil {
		return Config{}, err
	}

	// The current name wins when both are set. Connection config updates are
	// merged into the stored config, so an old alias written before a rename
	// stays stored next to the new name and must not override it.
	config := Config{
		CA:          pick(r.CA, r.LegacyCA),
		Certificate: pick(r.Certificate, r.LegacyCert),
		Key:         pick(r.Key, r.LegacyKey),
		ServerName:  r.ServerName,
		UseTLS:      r.UseTLS,
		CAPath:      pick(r.CAPath, r.LegacyCAPath),
	}
	switch {
	case r.SkipVerify != nil:
		config.SkipVerify = *r.SkipVerify
	case r.LegacySkip != nil:
		config.SkipVerify = *r.LegacySkip
	}

	if (config.Certificate == "") != (config.Key == "") {
		return Config{}, errors.New("both tls_certificate and tls_key are required for mutual TLS")
	}
	return config, nil
}

// pick returns value, falling back to its alias when value is empty.
func pick(value, alias string) string {
	if value != "" {
		return value
	}
	return alias
}

// Configured reports whether the plugin needs to construct a TLS transport.
func (c Config) Configured() bool {
	return c.UseTLS || c.CA != "" || c.CAPath != "" || c.Certificate != "" || c.ServerName != "" || c.SkipVerify
}

// Build constructs a TLS 1.2+ client configuration. When a CA is given, only
// that CA is trusted; otherwise the system roots are used.
func (c Config) Build(defaultServerName string) (*tls.Config, error) {
	serverName := c.ServerName
	if serverName == "" {
		serverName = defaultServerName
	}

	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: c.SkipVerify, //nolint:gosec // explicit operator opt-in
	}
	if c.CA != "" || c.CAPath != "" {
		roots := x509.NewCertPool()
		if c.CA != "" && !roots.AppendCertsFromPEM([]byte(c.CA)) {
			return nil, errors.New("failed to parse tls_ca PEM")
		}
		if c.CAPath != "" {
			pem, err := os.ReadFile(c.CAPath)
			if err != nil {
				return nil, fmt.Errorf("read tls_ca_path: %w", err)
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("failed to parse tls_ca_path PEM")
			}
		}
		config.RootCAs = roots
	}
	if c.Certificate != "" {
		certificate, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.Key))
		if err != nil {
			return nil, fmt.Errorf("failed to parse tls_certificate/tls_key: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}
