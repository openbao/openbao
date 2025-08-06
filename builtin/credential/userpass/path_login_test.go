// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

func TestPathLogin_TimingLeak(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)

	latency := physical.NewLatencyInjector(inm, 2*time.Second, 1, logger)
	cache := physical.NewCache(latency, 0, logger, &metrics.BlackholeSink{})
	storage := logical.NewLogicalStorage(cache)
	config := logical.TestBackendConfig()
	config.StorageView = storage

	ctx := namespace.RootContext(context.Background())
	b, err := Factory(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, b)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "users/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "password",
			"policies": "foo",
		},
	}

	// Create user
	_, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "invalid-password",
		},
	}

	start := time.Now()
	resp, err := b.HandleRequest(ctx, req)
	// ensuring we actually hit the storage
	require.Greater(t, time.Since(start).Seconds(), 2.01*time.Second.Seconds())
	require.Equal(t, resp.Data["error"], "invalid username or password")
	require.ErrorIs(t, err, logical.ErrInvalidCredentials)

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login/non-existing",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "invalid-password",
		},
	}

	start = time.Now()
	resp, err = b.HandleRequest(ctx, req)
	// ensuring we actually hit the storage
	require.Greater(t, time.Since(start).Seconds(), 2.01*time.Second.Seconds())
	require.Equal(t, resp.Data["error"], "invalid username or password")
	require.Nil(t, err)
}
