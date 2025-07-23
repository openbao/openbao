// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"context"
	"testing"

	"github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})
	cache.SetEnabled(true)
	physical.ExerciseBackend(t, cache)
	physical.ExerciseTransactionalBackend(t, cache.(physical.TransactionalBackend))
	physical.ExerciseBackend_ListPrefix(t, cache)
}

func TestCache_ModifyEntry(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})
	cache.SetEnabled(true)

	entry := &physical.Entry{
		Key:   "my-key",
		Value: []byte("my-initial-value"),
	}
	err = cache.Put(context.Background(), entry)
	require.NoError(t, err)

	entry.Value = []byte("my-modified-value")

	entryFromCache, err := cache.Get(context.Background(), entry.Key)
	require.NoError(t, err)

	require.NotEqual(t, string(entryFromCache.Value), string(entry.Value), "post-put modification to entry shouldn't affect cache")
	require.Equal(t, string(entryFromCache.Value), "my-initial-value", "cache should match the put value")
}

func TestCache_Purge(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})
	cache.SetEnabled(true)

	ent := &physical.Entry{
		Key:   "foo",
		Value: []byte("bar"),
	}
	err = cache.Put(context.Background(), ent)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Delete from under
	inm.Delete(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}

	// Read should work
	out, err := cache.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("should have key")
	}

	// Clear the cache
	cache.Purge(context.Background())

	// Read should fail
	out, err = cache.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Fatal("should not have key")
	}
}

func TestCache_Invalidate(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)
	require := require.New(t)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})
	cache.SetEnabled(true)

	// Store some value
	require.NoError(cache.Put(context.Background(), &physical.Entry{
		Key:   "foo",
		Value: []byte("bar"),
	}))

	// Start a transaction
	tx, err := cache.(physical.TransactionalBackend).BeginTx(context.Background())
	require.NoError(err)

	// Modify in under
	require.NoError(inm.Put(context.Background(), &physical.Entry{
		Key:   "foo",
		Value: []byte("bazz"),
	}))

	// Read should return old value
	out, err := cache.Get(context.Background(), "foo")
	require.NoError(err)
	require.NotNil(out, "should have key")
	require.EqualValues("bar", out.Value)

	// Read from transaction should return old value
	out, err = tx.Get(context.Background(), "foo")
	require.NoError(err)
	require.NotNil(out, "transaction should have key")
	require.EqualValues("bar", out.Value)

	// Clear the cache
	cache.Invalidate(context.Background(), "foo")

	// Read should return new value
	out, err = cache.Get(context.Background(), "foo")
	require.NoError(err)
	require.NotNil(out, "should have key")
	require.EqualValues("bazz", out.Value)

	// Read from transaction should still return old value
	out, err = tx.Get(context.Background(), "foo")
	require.NoError(err)
	require.NotNil(out, "transaction should have key")
	require.EqualValues("bar", out.Value)

	require.NoError(tx.Rollback(context.Background()))
}

func TestCache_Disable(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})

	disabledTests := func() {
		ent := &physical.Entry{
			Key:   "foo",
			Value: []byte("bar"),
		}
		err = inm.Put(context.Background(), ent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		// Read should work
		out, err := cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		err = inm.Delete(context.Background(), ent.Key)
		if err != nil {
			t.Fatal(err)
		}

		// Should not work
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out != nil {
			t.Fatal("should not have key")
		}

		// Put through the cache and try again
		err = cache.Put(context.Background(), ent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		// Read should work in both
		out, err = inm.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		err = inm.Delete(context.Background(), ent.Key)
		if err != nil {
			t.Fatal(err)
		}

		// Should not work
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out != nil {
			t.Fatal("should not have key")
		}
	}

	enabledTests := func() {
		ent := &physical.Entry{
			Key:   "foo",
			Value: []byte("bar"),
		}
		err = inm.Put(context.Background(), ent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		// Read should work
		out, err := cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		err = inm.Delete(context.Background(), ent.Key)
		if err != nil {
			t.Fatal(err)
		}

		// Should work
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		// Put through the cache and try again
		err = cache.Put(context.Background(), ent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		// Read should work for both
		out, err = inm.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		err = inm.Delete(context.Background(), ent.Key)
		if err != nil {
			t.Fatal(err)
		}

		// Should work
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		// Put through the cache
		err = cache.Put(context.Background(), ent)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		// Read should work for both
		out, err = inm.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out == nil {
			t.Fatal("should have key")
		}

		// Delete via cache
		err = cache.Delete(context.Background(), ent.Key)
		if err != nil {
			t.Fatal(err)
		}

		// Read should not work for either
		out, err = inm.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out != nil {
			t.Fatal("should not have key")
		}
		out, err = cache.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if out != nil {
			t.Fatal("should not have key")
		}
	}

	disabledTests()
	cache.SetEnabled(true)
	enabledTests()
	cache.SetEnabled(false)
	disabledTests()
}

func TestCache_Refresh(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	cache := physical.NewCache(inm, 0, logger, &metrics.BlackholeSink{})
	cache.SetEnabled(true)

	ent := &physical.Entry{
		Key:   "foo",
		Value: []byte("bar"),
	}
	err = cache.Put(context.Background(), ent)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ent2 := &physical.Entry{
		Key:   "foo",
		Value: []byte("baz"),
	}
	// Update below cache
	err = inm.Put(context.Background(), ent2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	r, err := cache.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if string(r.Value) != "bar" {
		t.Fatalf("expected value bar, got %s", string(r.Value))
	}

	// Refresh the cache
	r, err = cache.Get(physical.CacheRefreshContext(context.Background(), true), "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if string(r.Value) != "baz" {
		t.Fatalf("expected value baz, got %s", string(r.Value))
	}

	// Make sure new value is in cache
	r, err = cache.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(r.Value) != "baz" {
		t.Fatalf("expected value baz, got %s", string(r.Value))
	}
}
