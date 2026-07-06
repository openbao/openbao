// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
)

// HubState is the runtime hub identity shared between the logical backend
// (which mutates it during `bao relay init` and CA rotation) and the proxy
// gRPC server (which reads it when configuring its TLS listener).
//
// We keep it as a package-level singleton because the logical backend runs in
// the same process as the database-plugin proxy: both are compiled into the
// `bao` binary via helper/builtinplugins/registry.go. A singleton is the
// cheapest IPC available.
type HubState struct {
	mu sync.RWMutex

	caCertPEM    []byte // spoke-CA root, distributed to spokes
	caKeyPEM     []byte // spoke-CA private key, used to sign renewal CSRs
	hubCertPEM   []byte // hub TLS cert (signed by spoke-CA)
	hubKeyPEM    []byte
	clientCAPool *x509.CertPool // pool used by the proxy mTLS listener
	hubTLSCert   *tls.Certificate
}

var globalHubState = &HubState{}

// Global returns the process-wide hub state.
func Global() *HubState { return globalHubState }

// SetIdentity replaces the hub's CA + server cert. Called by the logical
// backend on `relay/ca/init` and again on CA rotation. Safe to call before any
// gRPC connection arrives; the proxy listener reads via TLSConfig callbacks
// every handshake.
//
// Verifies the hub cert chains to the supplied CA before publishing the new
// identity. A storage corruption or operator misuse that paired the hub cert
// from one CA with the public cert of a different CA would otherwise only
// surface on the first incoming TLS handshake — too late to recover without
// touching every spoke.
func (s *HubState) SetIdentity(ca *CABundle, hub *HubServerCert) error {
	if ca == nil || hub == nil {
		return fmt.Errorf("nil CA or hub cert")
	}
	tlsCert, err := tls.X509KeyPair(hub.CertPEM, hub.KeyPEM)
	if err != nil {
		return fmt.Errorf("load hub TLS cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		return fmt.Errorf("ca PEM did not yield any usable certs")
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse hub leaf cert: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		return fmt.Errorf("hub cert does not chain to the supplied spoke CA: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCertPEM = append([]byte(nil), ca.CertPEM...)
	s.caKeyPEM = append([]byte(nil), ca.KeyPEM...)
	s.hubCertPEM = append([]byte(nil), hub.CertPEM...)
	s.hubKeyPEM = append([]byte(nil), hub.KeyPEM...)
	s.clientCAPool = pool
	s.hubTLSCert = &tlsCert
	return nil
}

// CACertPEM returns a copy of the spoke-CA cert PEM. Empty before init.
func (s *HubState) CACertPEM() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.caCertPEM...)
}

// CABundlePEM returns the (cert, key) PEM pair needed for signing CSRs (e.g.
// the gRPC RenewCert RPC). Empty when the hub is not yet initialized.
func (s *HubState) CABundlePEM() (certPEM []byte, keyPEM []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.caCertPEM...), append([]byte(nil), s.caKeyPEM...)
}

// Ready reports whether SetIdentity has been called successfully.
func (s *HubState) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hubTLSCert != nil
}

// TLSConfig returns a server TLS config suitable for grpc.NewServer with
// mTLS enabled. The returned config reads `s` on every handshake, so identity
// rotation takes effect on the next connection without restarting the server.
func (s *HubState) TLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.hubTLSCert == nil {
				return nil, fmt.Errorf("hub identity not initialized; run `bao relay init`")
			}
			return s.hubTLSCert, nil
		},
		ClientCAs: nil, // see GetConfigForClient
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.clientCAPool == nil {
				return nil, fmt.Errorf("spoke CA not initialized")
			}
			return &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    s.clientCAPool,
				Certificates: []tls.Certificate{*s.hubTLSCert},
				// TLS 1.3 floor: this is a brand-new, closed hub↔spoke
				// ecosystem where both sides run the same bao binary, so
				// there is no compatibility cost to refusing 1.2.
				MinVersion: tls.VersionTLS13,
			}, nil
		},
		MinVersion: tls.VersionTLS13,
	}
}
