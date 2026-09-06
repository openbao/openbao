// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInmem(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	physical.ExerciseBackend(t, inm)
	physical.ExerciseTransactionalBackend(t, inm.(physical.TransactionalBackend))
	physical.ExerciseBackend_ListPrefix(t, inm)
}

func TestInmem_TransactionLeak(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	inmt := inm.(*TransactionalInmemBackend)

	// start transaction
	tx, err := inmt.BeginTx(t.Context())
	require.NoError(t, err)

	var callCount atomic.Int64
	// Because we can't catch the panic in the cleanup hook (it runs in a
	// dedicated go routine), we have to wrap the hook and do the asserts there.
	originalHook := inmt.leakedTransactionHook
	inmt.leakedTransactionHook = func(args []any) {
		callCount.Add(1)
		if assert.Len(t, args, 2) {
			assert.Equal(t, "stack", args[0])
			assert.Contains(t, args[1], ".BeginTx(")
			assert.Contains(t, args[1], t.Name())
		}
		assert.Panics(t, func() {
			originalHook(args)
		}, "default hook should panic, if in testing")
	}

	_, err = tx.List(t.Context(), "list/me")
	require.NoError(t, err)

	_, err = tx.Get(t.Context(), "read/me")
	require.NoError(t, err)

	err = tx.Put(t.Context(), &physical.Entry{
		Key:   "write/me",
		Value: []byte("value"),
	})
	require.NoError(t, err)

	err = tx.Delete(t.Context(), "delete/me")
	require.NoError(t, err)

	// leak transaction
	tx = nil

	// wait for hook
	for range 100 {
		runtime.GC()

		if callCount.Load() == 1 {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	assert.Equal(t, int64(1), callCount.Load(), "expected hook to be called once")

	// assert clean-up
	assert.Equal(t, 0, inmt.txnPermitPool.CurrentPermits())
}
