package kmip

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go/kmipserver"
)

type Server struct {
	srv        *kmipserver.Server
	listener   net.Listener
	b          logical.Backend
	listenAddr string
}

func NewServer(b logical.Backend, cfg ServerConfig) (*Server, error) {
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

	registerHandlers(executor, b)
	srv := kmipserver.NewServer(listener, executor)

	return &Server{
		srv:        srv,
		listener:   listener,
		b:          b,
		listenAddr: cfg.ListenAddr,
	}, nil
}

func (s *Server) Start() {
	go func() {
		if err := s.srv.Serve(); err != nil {
			s.b.Logger().Error("KMIP server stopped with error", "error", err)
		}
	}()
}

func (s *Server) Stop() error {
	return s.srv.Shutdown()
}
