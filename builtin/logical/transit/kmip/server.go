// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/ovh/kmip-go/kmipserver"
)

type Server struct {
	srv           *kmipserver.Server
	listener      net.Listener
	listenAddr    string
	adapter       Adapter
	cryptoAdapter CryptoAdapter
}

func NewServer(a Adapter, cryptoA CryptoAdapter, cfg ServerConfig) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPem, cfg.KeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	listener, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
	}

	executor := kmipserver.NewBatchExecutor()

	executor.Use(authMiddleware(a))
	registerHandlers(executor, a)
	srv := kmipserver.NewServer(listener, executor)

	return &Server{
		srv:           srv,
		listener:      listener,
		listenAddr:    cfg.ListenAddr,
		adapter:       a,
		cryptoAdapter: cryptoA,
	}, nil
}

func (s *Server) Start() {
	go func() {
		if err := s.srv.Serve(); err != nil {
			s.adapter.Logger().Error("KMIP server stopped with error", "error", err)
		}
	}()
}

func (s *Server) Stop() error {
	return s.srv.Shutdown()
}
