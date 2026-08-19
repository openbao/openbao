// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/openbao/openbao/sdk/v2/physical"
)

var (
	minBackoff     = 2 * time.Millisecond
	defaultBackoff = 5 * time.Millisecond
)

type indexManager struct {
	backend       physical.ReplicationIndexBackend
	invalidations *invalidationManager

	backoff time.Duration

	indexLock       sync.RWMutex
	lastIndex       string
	lastIndexUpdate time.Time

	outstandingLock    sync.RWMutex
	outstandingIndices []string
	outstandingUpdate  time.Time
}

func NewIndexManager(backend physical.ReplicationIndexBackend, invalidations *invalidationManager, backoff time.Duration) *indexManager {
	if backoff == 0 {
		backoff = defaultBackoff
	} else if backoff < minBackoff {
		backoff = minBackoff
	}

	return &indexManager{
		backend:       backend,
		invalidations: invalidations,
		backoff:       backoff,
	}
}

// Latest always refreshes the index, returning the latest.
func (i *indexManager) Latest(ctx context.Context) (string, error) {
	i.indexLock.Lock()
	defer i.indexLock.Unlock()

	return i.getIndexLocked(ctx)
}

func (core *Core) MaybeGetLatestStorageIndex(ctx context.Context) string {
	if core.indexManager == nil {
		return ""
	}

	idx, err := core.indexManager.Latest(ctx)
	if err != nil {
		return ""
	}

	return idx
}

// Get returns the latest index if it is within freshness thresholds.
func (i *indexManager) Get(ctx context.Context) (string, error) {
	if index := func() string {
		i.indexLock.RLock()
		defer i.indexLock.RUnlock()

		if time.Now().After(i.lastIndexUpdate.Add(i.backoff)) {
			return ""
		}

		return i.lastIndex
	}(); index != "" {
		return index, nil
	}

	i.indexLock.Lock()
	defer i.indexLock.Unlock()

	return i.getIndexLocked(ctx)
}

func (core *Core) HaveSeenStorageIndex(ctx context.Context, index string) (bool, error) {
	if core.indexManager == nil {
		return true, nil
	}

	current, err := core.indexManager.Get(ctx)
	if err != nil {
		return false, err
	}

	seen, err := core.indexManager.backend.GreaterEqualReplicationIndex(ctx, current, index)
	if err != nil || !seen {
		return seen, err
	}

	// We've seen the index, so check if we've handled all prior
	// invalidations.
	outstanding := core.indexManager.GetOutstanding()
	for _, pending := range outstanding {
		older, err := core.indexManager.backend.GreaterEqualReplicationIndex(ctx, index, pending)
		if err != nil || older {
			// We have an older index still waiting for its invalidation job to
			// complete; this means we need to wait.
			return false, err
		}
	}

	return true, nil
}

func (i *indexManager) Await(ctx context.Context, index string) error {
	// Before checking the underlying index, check if we're already past our
	// last-seen index.

	i.indexLock.RLock()
	first := i.lastIndex
	i.indexLock.RUnlock()
	if first != "" {
		if passed, err := i.backend.GreaterEqualReplicationIndex(ctx, first, index); err == nil && passed {
			return nil
		}
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = i.backoff
	b.MaxInterval = 1 * time.Second

	timeBoxed, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	op := func() (none struct{}, err error) {
		current, err := i.Get(timeBoxed)
		if err != nil {
			return none, err
		}

		passed, err := i.backend.GreaterEqualReplicationIndex(timeBoxed, current, index)
		if err != nil {
			return none, err
		}

		if !passed {
			return none, errors.New("not yet reached specified storage index")
		}

		return none, nil
	}

	_, err := backoff.Retry(timeBoxed, op, backoff.WithBackOff(b))
	return err
}

// AwaitInvalidated first calls Await and then additionally awaits for all
// outstanding older invalidations to be concluded.
func (i *indexManager) AwaitInvalidated(ctx context.Context, index string) error {
	timeBoxed, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if err := i.Await(ctx, index); err != nil {
		return fmt.Errorf("error awaiting underlying storage replication: %w", err)
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = i.backoff
	b.MaxInterval = 1 * time.Second

	op := func() (none struct{}, err error) {
		outstanding := i.GetOutstanding()

		for _, pending := range outstanding {
			older, err := i.backend.GreaterEqualReplicationIndex(ctx, index, pending)
			if err != nil || older {
				// We have an older index still waiting for its invalidation job to
				// complete; this means we need to wait.
				return none, fmt.Errorf("still have outstanding replication index %v: %w", pending, err)
			}
		}

		return none, nil
	}

	_, err := backoff.Retry(timeBoxed, op, backoff.WithBackOff(b))
	return err
}

func (core *Core) AwaitStorageIndex(ctx context.Context, index string) bool {
	if core.indexManager == nil {
		return true
	}

	if seen, err := core.HaveSeenStorageIndex(ctx, index); err == nil && seen {
		return true
	}

	return core.indexManager.AwaitInvalidated(ctx, index) == nil
}

func (i *indexManager) getIndexLocked(ctx context.Context) (string, error) {
	// Assume the index is relative to the start of the check operation,
	// not the end.
	when := time.Now()

	storageIndex, err := i.backend.AppliedReplicationIndex(ctx)
	if err != nil {
		return "", fmt.Errorf("error checking replication index: %w", err)
	}

	if i.lastIndex != storageIndex {
		// Reset outstanding: we may be processing this index still.
		i.outstandingLock.Lock()
		i.outstandingIndices = nil
		i.outstandingLock.Unlock()
	}

	i.lastIndex = storageIndex
	i.lastIndexUpdate = when

	return storageIndex, nil
}

// getOutstanding returns the outstanding indices that need to be invalidated,
// if it is within freshness thresholds.
func (i *indexManager) GetOutstanding() []string {
	if outstanding := func() []string {
		i.outstandingLock.RLock()
		defer i.outstandingLock.RUnlock()

		if time.Now().After(i.outstandingUpdate.Add(i.backoff)) {
			return nil
		}

		return i.outstandingIndices
	}(); outstanding != nil {
		return outstanding
	}

	i.outstandingLock.Lock()
	defer i.outstandingLock.Unlock()

	return i.getOutstandingLocked()
}

func (i *indexManager) getOutstandingLocked() []string {
	// Assume the outstanding set is relative to the start of the check
	// operation, not the end.
	when := time.Now()
	outstanding := i.invalidations.OutstandingInvalidationIndices()
	if len(outstanding) == 0 {
		// Ensure we're strictly non-nil to differentiate in getOutstanding(...).
		outstanding = []string{}
	}

	i.outstandingIndices = outstanding
	i.outstandingUpdate = when

	return i.outstandingIndices
}
