// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
)

type KVv1 struct {
	c         *Client
	mountPath string
}

// Get returns a secret from the KV v1 secrets engine.
func (kv *KVv1) Get(ctx context.Context, secretPath string) (*KVSecret, error) {
	pathToRead := fmt.Sprintf("%s/%s", kv.mountPath, secretPath)

	secret, err := kv.c.Logical().ReadWithContext(ctx, pathToRead)
	if err != nil {
		return nil, fmt.Errorf("error encountered while reading secret at %s: %w", pathToRead, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%w: at %s", ErrSecretNotFound, pathToRead)
	}

	return &KVSecret{
		Data:            secret.Data,
		VersionMetadata: nil,
		Raw:             secret,
	}, nil
}

// Put inserts a key-value secret (e.g. {"password": "password123"}) into the
// KV v1 secrets engine.
//
// If the secret already exists, it will be overwritten.
func (kv *KVv1) Put(ctx context.Context, secretPath string, data map[string]any) error {
	pathToWriteTo := fmt.Sprintf("%s/%s", kv.mountPath, secretPath)

	_, err := kv.c.Logical().WriteWithContext(ctx, pathToWriteTo, data)
	if err != nil {
		return fmt.Errorf("error writing secret to %s: %w", pathToWriteTo, err)
	}

	return nil
}

// Delete deletes a secret from the KV v1 secrets engine.
func (kv *KVv1) Delete(ctx context.Context, secretPath string) error {
	pathToDelete := fmt.Sprintf("%s/%s", kv.mountPath, secretPath)

	_, err := kv.c.Logical().DeleteWithContext(ctx, pathToDelete)
	if err != nil {
		return fmt.Errorf("error deleting secret at %s: %w", pathToDelete, err)
	}

	return nil
}

// List returns the list of available keys at the specified location.
func (kv *KVv1) List(ctx context.Context, secretPath string) (*KVList, error) {
	pathToList := fmt.Sprintf("%s/%s", kv.mountPath, secretPath)

	resp, err := kv.c.Logical().ListWithContext(ctx, pathToList)
	if err != nil {
		return nil, fmt.Errorf("error listing secrets at %s: %w", pathToList, err)
	}

	return extractKeyList(resp)
}

// Scan returns the list of available keys at the specified location, recursing
// into sub-folders.
func (kv *KVv1) Scan(ctx context.Context, secretPath string) (*KVList, error) {
	pathToList := fmt.Sprintf("%s/%s", kv.mountPath, secretPath)

	resp, err := kv.c.Logical().ScanWithContext(ctx, pathToList)
	if err != nil {
		return nil, fmt.Errorf("error listing secrets at %s: %w", pathToList, err)
	}

	return extractKeyList(resp)
}
