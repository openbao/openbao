// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"sync"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/physical/inmem"
	"github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

func TestCore_Init(t *testing.T) {
	testCoreInitCommon(t, nil, &SealConfig{SecretShares: 5, SecretThreshold: 3}, nil)

	testSeal, _ := seal.NewTestSeal(&seal.TestSealOpts{Wrapper: wrapping.WrapperTypeTest})
	autoSeal, err := NewAutoSeal(testSeal)
	require.NoError(t, err)
	testCoreInitCommon(t, autoSeal, &SealConfig{SecretShares: 1, SecretThreshold: 1}, &SealConfig{SecretShares: 0, SecretThreshold: 0})
}

func testCoreNewTestCore(t *testing.T, seal Seal) (*Core, *CoreConfig) {
	logger := logging.NewVaultLogger(log.Trace)
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)

	conf := &CoreConfig{
		Physical: inm,
		LogicalBackends: map[string]logical.Factory{
			"kv": LeasedPassthroughBackendFactory,
		},
		Seal: seal,
	}
	c, err := NewCore(conf)
	require.NoError(t, err)

	t.Cleanup(func() {
		defer func() {
			if r := recover(); r != nil {
				t.Log("panic closing core during cleanup", "panic", r)
			}
		}()
		c.Shutdown()
	})
	return c, conf
}

func testCoreInitCommon(t *testing.T, s Seal, barrierConf, recoveryConf *SealConfig) {
	c, conf := testCoreNewTestCore(t, s)
	ctx := namespace.RootContext(t.Context())
	init, err := c.Initialized(ctx)
	require.NoError(t, err)
	require.False(t, init)

	// Check the seal configuration
	outConf, err := c.seal.BarrierConfig(ctx)
	require.NoError(t, err)
	require.Empty(t, outConf)

	if recoveryConf != nil {
		outConf, err := c.seal.RecoveryConfig(ctx)
		require.NoError(t, err)
		require.Empty(t, outConf)
	}

	res, err := c.Initialize(ctx, &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.NoError(t, err)

	require.Falsef(
		t,
		c.seal.BarrierType() == seal.WrapperTypeShamir && len(res.SecretShares) != barrierConf.SecretShares,
		"Bad: got\n%#v\nexpected conf matching\n%#v\n", *res, *barrierConf,
	)

	if recoveryConf != nil {
		require.Falsef(
			t,
			len(res.RecoveryShares) != recoveryConf.SecretShares,
			"Bad: got\n%#v\nexpected conf matching\n%#v\n", *res, *recoveryConf,
		)
	}

	require.NotEmpty(t, res.RootToken)

	_, err = c.Initialize(ctx, &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.ErrorIs(t, err, ErrAlreadyInit)

	init, err = c.Initialized(ctx)
	require.NoError(t, err)
	require.True(t, init)

	// Check the seal configuration
	outConf, err = c.seal.BarrierConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, barrierConf, outConf)

	if recoveryConf != nil {
		outConf, err = c.seal.RecoveryConfig(ctx)
		require.NoError(t, err)
		require.Equal(t, recoveryConf, outConf)
	}

	// New Core, same backend
	c2, err := NewCore(conf)
	require.NoError(t, err)

	_, err = c2.Initialize(ctx, &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.ErrorIs(t, err, ErrAlreadyInit)

	init, err = c2.Initialized(ctx)
	require.NoError(t, err)
	require.True(t, init)

	// Check the seal configuration
	outConf, err = c2.seal.BarrierConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, barrierConf, outConf)

	if recoveryConf != nil {
		outConf, err = c2.seal.RecoveryConfig(ctx)
		require.NoError(t, err)
		require.Equal(t, recoveryConf, outConf)
	}
}

func TestCore_InitParallelRequests(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)

	inm, err := inmem.NewInmemHA(nil, logger)
	require.NoError(t, err)

	inmha, err := inmem.NewInmemHA(nil, logger)
	require.NoError(t, err)

	redirectOriginal := "http://127.0.0.1:8200"
	conf := &CoreConfig{
		Physical:   inm,
		HAPhysical: inmha.(physical.HABackend),
		LogicalBackends: map[string]logical.Factory{
			"kv": LeasedPassthroughBackendFactory,
		},
		RedirectAddr: redirectOriginal,
		DisableCache: true,
		Seal:         nil,
	}
	c, err := NewCore(conf)
	require.NoError(t, err)

	t.Cleanup(func() {
		c.Shutdown() //nolint:errcheck
	})

	ctx := namespace.RootContext(t.Context())
	init, err := c.Initialized(ctx)
	require.NoError(t, err)
	require.False(t, init)

	var wg sync.WaitGroup
	spamCtx, cancel := context.WithCancel(t.Context())
	defer cancel()

	for range 32 {
		wg.Go(func() {
			for {
				if spamCtx.Err() != nil {
					return
				}

				// We don't actually care about anything here.
				c.HandleRequest(ctx, &logical.Request{ //nolint:errcheck
					Path:      "sys/mounts/kv",
					Operation: logical.CreateOperation,
					Data: map[string]any{
						"type": "kv",
					},
				})
			}
		})
	}

	time.Sleep(150 * time.Millisecond)

	resp, err := c.Initialize(ctx, &InitParams{
		BarrierConfig: &SealConfig{SecretShares: 5, SecretThreshold: 3},
	})
	require.NoError(t, err)

	for _, key := range resp.SecretShares {
		_, err := TestCoreUnseal(c, key)
		require.NoError(t, err)
	}

	time.Sleep(2 * time.Second)

	cancel()
	wg.Wait()
}
