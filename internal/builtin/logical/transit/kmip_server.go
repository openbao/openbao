// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"

	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// getKmipConfig retrieves the KMIP server configuration from storage
func (b *backend) getKmipConfig(ctx context.Context, s logical.Storage) (kmip.ServerConfig, error) {
	entry, err := s.Get(ctx, kmip.ConfigStoragePath)
	if err != nil {
		return kmip.ServerConfig{}, err
	}
	if entry == nil {
		return kmip.ServerConfig{}, nil
	}

	var cfg kmip.ServerConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return kmip.ServerConfig{}, err
	}

	return cfg, nil
}

// restartKmipServer starts or stops the KMIP server based on the provided configuration
func (b *backend) restartKmipServer(cfg kmip.ServerConfig, s logical.Storage) error {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	if !cfg.Enabled {
		if b.kmipServer != nil {
			if err := b.kmipServer.Stop(); err != nil {
				b.Logger().Error("stop KMIP server", "error", err)
			}
			b.kmipServer = nil
		}
		return nil
	}

	a := &transitAdapter{b: b, s: s}

	srv, err := kmip.NewServer(a, a, cfg)
	if err != nil {
		return err
	}

	srv.Start()
	b.kmipServer = srv
	return nil
}

func (b *backend) stopKmipServer() {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	if b.kmipServer != nil {
		if err := b.kmipServer.Stop(); err != nil {
			b.Logger().Error("stop KMIP server", "error", err)
		}
		b.kmipServer = nil
	}
}
