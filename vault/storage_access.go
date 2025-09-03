// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
)

type StorageAccess interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	ListPage(context.Context, string, string, int) ([]string, error)
}

var (
	_ StorageAccess = (*directStorageAccess)(nil)
	_ StorageAccess = (*secureStorageAccess)(nil)
)

type directStorageAccess struct {
	physical physical.Backend
}

func (p *directStorageAccess) Put(ctx context.Context, path string, value []byte) error {
	pe := &physical.Entry{
		Key:   path,
		Value: value,
	}
	return p.physical.Put(ctx, pe)
}

func (p *directStorageAccess) Get(ctx context.Context, path string) ([]byte, error) {
	pe, err := p.physical.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if pe == nil {
		return nil, nil
	}
	return pe.Value, nil
}

func (p *directStorageAccess) Delete(ctx context.Context, key string) error {
	return p.physical.Delete(ctx, key)
}

func (p *directStorageAccess) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return p.physical.ListPage(ctx, prefix, after, limit)
}

type secureStorageAccess struct {
	barrier SecurityBarrier
}

func (b *secureStorageAccess) Put(ctx context.Context, path string, value []byte) error {
	se := &logical.StorageEntry{
		Key:   path,
		Value: value,
	}
	return b.barrier.Put(ctx, se)
}

func (b *secureStorageAccess) Get(ctx context.Context, path string) ([]byte, error) {
	se, err := b.barrier.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if se == nil {
		return nil, nil
	}
	return se.Value, nil
}

func (b *secureStorageAccess) Delete(ctx context.Context, key string) error {
	return b.barrier.Delete(ctx, key)
}

func (b *secureStorageAccess) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return b.barrier.ListPage(ctx, prefix, after, limit)
}
