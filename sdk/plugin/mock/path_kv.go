// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mock

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// kvPaths is used to test CRUD and List operations. It is a simplified
// version of the passthrough backend that only accepts string values.
func kvPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "kv/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKVList,
				},
			},
		},
		{
			Pattern: "kv/" + framework.GenericNameRegex("key"),
			Fields: map[string]*framework.FieldSchema{
				"key":     {Type: framework.TypeString},
				"value":   {Type: framework.TypeString},
				"version": {Type: framework.TypeInt},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKVRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKVCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKVCreateUpdate,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathKVDelete,
				},
			},
		},
	}
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *backend) pathKVRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	version := data.Get("version").(int)

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	value := string(entry.Value)

	b.Logger().Info("reading value", "key", req.Path, "value", value)
	// Return the secret
	resp := &logical.Response{
		Data: map[string]interface{}{
			"value":   value,
			"version": version,
		},
	}
	if version != 0 {
		resp.Data["version"] = version
	}
	return resp, nil
}

func (b *backend) pathKVCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	value := data.Get("value").(string)

	b.Logger().Info("storing value", "key", req.Path, "value", value)
	entry := &logical.StorageEntry{
		Key:   req.Path,
		Value: []byte(value),
	}

	s := req.Storage
	err := s.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"value": value,
		},
	}, nil
}

func (b *backend) pathKVDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathKVList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "kv/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}
