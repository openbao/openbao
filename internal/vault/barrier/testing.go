// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package barrier

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/physical/inmem"
	"github.com/stretchr/testify/require"
)

// MockBarrier returns a physical backend, security barrier, and root key
func MockBarrier(t testing.TB, logger hclog.Logger) (physical.Backend, SecurityBarrier, []byte) {
	inm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err)
	b := NewAESGCMBarrier(inm, nil)

	// Initialize and unseal
	key, _ := b.GenerateKey()
	err = b.Initialize(t.Context(), key, nil)
	require.NoError(t, err)
	err = b.Unseal(t.Context(), key)
	require.NoError(t, err)
	return inm, b, key
}
