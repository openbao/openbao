// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	log "github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault/seal"
	"github.com/stretchr/testify/require"
)

func TestCore_Init(t *testing.T) {
	testCoreInitCommon(t, nil, &SealConfig{SecretShares: 5, SecretThreshold: 3}, nil)

	testSeal, _ := seal.NewTestSeal(&seal.TestSealOpts{Name: "transit"})
	autoSeal, err := NewAutoSeal(testSeal)
	require.NoError(t, err)
	testCoreInitCommon(t, autoSeal, &SealConfig{SecretShares: 1, SecretThreshold: 1}, &SealConfig{SecretShares: 0, SecretThreshold: 0})
}

func testCoreNewTestCoreLicensing(t *testing.T, seal Seal) (*Core, *CoreConfig) {
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

func testCoreInitCommon(t *testing.T, seal Seal, barrierConf, recoveryConf *SealConfig) {
	c, conf := testCoreNewTestCoreLicensing(t, seal)
	init, err := c.Initialized(context.Background())
	require.NoError(t, err)
	require.False(t, init)

	// Check the seal configuration
	outConf, err := c.seal.BarrierConfig(context.Background())
	require.NoError(t, err)
	require.Empty(t, outConf)

	if recoveryConf != nil {
		outConf, err := c.seal.RecoveryConfig(context.Background())
		require.NoError(t, err)
		require.Empty(t, outConf)
	}

	res, err := c.Initialize(context.Background(), &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.NoError(t, err)

	require.Falsef(t,
		c.seal.BarrierType() == wrapping.WrapperTypeShamir && len(res.SecretShares) != barrierConf.SecretShares,
		"Bad: got\n%#v\nexpected conf matching\n%#v\n", *res, *barrierConf,
	)

	if recoveryConf != nil {
		require.Falsef(t,
			len(res.RecoveryShares) != recoveryConf.SecretShares,
			"Bad: got\n%#v\nexpected conf matching\n%#v\n", *res, *recoveryConf,
		)
	}

	require.NotEmpty(t, res.RootToken)

	_, err = c.Initialize(context.Background(), &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.ErrorIs(t, err, ErrAlreadyInit)

	init, err = c.Initialized(context.Background())
	require.NoError(t, err)
	require.True(t, init)

	// Check the seal configuration
	outConf, err = c.seal.BarrierConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, barrierConf, outConf)

	if recoveryConf != nil {
		outConf, err = c.seal.RecoveryConfig(context.Background())
		require.NoError(t, err)
		require.Equal(t, recoveryConf, outConf)
	}

	// New Core, same backend
	c2, err := NewCore(conf)
	require.NoError(t, err)

	_, err = c2.Initialize(context.Background(), &InitParams{
		BarrierConfig:  barrierConf,
		RecoveryConfig: recoveryConf,
	})
	require.ErrorIs(t, err, ErrAlreadyInit)

	init, err = c2.Initialized(context.Background())
	require.NoError(t, err)
	require.True(t, init)

	// Check the seal configuration
	outConf, err = c2.seal.BarrierConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, barrierConf, outConf)

	if recoveryConf != nil {
		outConf, err = c2.seal.RecoveryConfig(context.Background())
		require.NoError(t, err)
		require.Equal(t, recoveryConf, outConf)
	}
}
