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
	backend physical.ReplicationIndexBackend
	backoff time.Duration

	l          sync.RWMutex
	lastIndex  string
	lastUpdate time.Time
}

func NewIndexManager(backend physical.ReplicationIndexBackend, backoff time.Duration) *indexManager {
	if backoff == 0 {
		backoff = defaultBackoff
	} else if backoff < minBackoff {
		backoff = minBackoff
	}

	return &indexManager{
		backend: backend,
		backoff: backoff,
	}
}

// Latest always refreshes the index, returning the latest.
func (i *indexManager) Latest(ctx context.Context) (string, error) {
	i.l.Lock()
	defer i.l.Unlock()

	return i.getIndexLocked(ctx)
}

// Get returns the latest index if it is within freshness thresholds.
func (i *indexManager) Get(ctx context.Context) (string, error) {
	if index := func() string {
		i.l.RLock()
		defer i.l.RUnlock()

		if time.Now().After(i.lastUpdate.Add(i.backoff)) {
			return ""
		}

		return i.lastIndex
	}(); index != "" {
		return index, nil
	}

	i.l.Lock()
	defer i.l.Unlock()

	return i.getIndexLocked(ctx)
}

func (i *indexManager) Await(ctx context.Context, index string) error {
	// Before checking the underlying index, check if we're already past our
	// last-seen index.

	i.l.RLock()
	first := i.lastIndex
	i.l.RUnlock()
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

func (i *indexManager) getIndexLocked(ctx context.Context) (string, error) {
	// Assume the index is relative to the start of the check operation,
	// not the end.
	when := time.Now()

	storageIndex, err := i.backend.AppliedReplicationIndex(ctx)
	if err != nil {
		return "", fmt.Errorf("error checking replication index: %w", err)
	}

	i.lastIndex = storageIndex
	i.lastUpdate = when

	return storageIndex, nil
}
