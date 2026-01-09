// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"sync"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
)

// InmemStorage implements Storage and stores all data in memory. It is
// basically a straight copy of physical.Inmem, but it prevents backends from
// having to load all of physical's dependencies (which are legion) just to
// have some testing storage.
type InmemStorage struct {
	underlying physical.Backend
	once       sync.Once
}

func (s *InmemStorage) Get(ctx context.Context, key string) (*StorageEntry, error) {
	s.once.Do(s.init)

	entry, err := s.underlying.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &StorageEntry{
		Key:      entry.Key,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	}, nil
}

func (s *InmemStorage) Put(ctx context.Context, entry *StorageEntry) error {
	s.once.Do(s.init)

	return s.underlying.Put(ctx, &physical.Entry{
		Key:      entry.Key,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	})
}

func (s *InmemStorage) Delete(ctx context.Context, key string) error {
	s.once.Do(s.init)

	return s.underlying.Delete(ctx, key)
}

func (s *InmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.once.Do(s.init)

	return s.underlying.List(ctx, prefix)
}

func (s *InmemStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	s.once.Do(s.init)

	return s.underlying.ListPage(ctx, prefix, after, limit)
}

func (s *InmemStorage) Underlying() *inmem.InmemBackend {
	s.once.Do(s.init)

	ts, ok := s.underlying.(*inmem.TransactionalInmemBackend)
	if ok {
		return &ts.InmemBackend
	}

	return s.underlying.(*inmem.InmemBackend)
}

func (s *InmemStorage) FailPut() *InmemStorage {
	s.Underlying().FailPut()
	return s
}

func (s *InmemStorage) FailGet() *InmemStorage {
	s.Underlying().FailGet()
	return s
}

func (s *InmemStorage) FailDelete() *InmemStorage {
	s.Underlying().FailDelete()
	return s
}

func (s *InmemStorage) FailList() *InmemStorage {
	s.Underlying().FailList()
	return s
}

func (s *InmemStorage) init() {
	s.underlying, _ = inmem.NewInmem(nil, nil)
}
