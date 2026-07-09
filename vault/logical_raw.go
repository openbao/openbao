// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/compressutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
)

// protectedPaths cannot be accessed via the raw APIs.
// This is both for security and to prevent disrupting Vault.
var protectedPaths = []string{
	barrier.KeyringPath,
	// Changing the cluster info path can change the cluster ID which can be disruptive
	coreLocalClusterInfoPath,
}

type RawBackend struct {
	*framework.Backend
	core   *Core
	logger log.Logger
}

func NewRawBackend(core *Core) *RawBackend {
	r := &RawBackend{
		core:   core,
		logger: core.logger.Named("raw"),
	}

	r.Backend = &framework.Backend{
		Paths: r.rawPaths("sys/"),
	}
	return r
}

// storageByPath returns appriopriate StorageAccess wrapping over specific
// namespace barrier depending on the requested path. Also returns if the
// namespace with given path (uuid) doesn't exist.
func (b *RawBackend) storageByPath(ctx context.Context, path string) (StorageAccess, bool, error) {
	ns, rest, err := b.core.NamespaceByStoragePath(ctx, path)
	if err != nil {
		return nil, false, err
	}

	// check if we are trying to access protected path.
	for _, p := range protectedPaths {
		if strings.HasPrefix(rest, p) {
			return nil, false, fmt.Errorf("cannot access %q", rest)
		}
	}

	// These paths use the "upper" barrier, which is the direct physical layer
	// for the root namespace.
	specialPath := rest == barrierSealConfigPath || rest == recoverySealConfigPath

	// Fast-path root or deleted namespaces; we do not need a lookup into the
	// seal manager.
	if ns == nil || ns.ID == namespace.RootNamespaceID {
		if specialPath {
			return &directStorageAccess{physical: b.core.physical}, ns != nil, nil
		} else {
			return &secureStorageAccess{barrier: b.core.barrier}, ns != nil, nil
		}
	}

	if specialPath {
		parent, _ := ns.ParentPath()
		return &secureStorageAccess{barrier: b.core.sealManager.NamespaceBarrierByLongestPrefix(parent)}, ns != nil, nil
	} else {
		return &secureStorageAccess{barrier: b.core.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)}, ns != nil, nil
	}
}

// handleRawRead is used to read directly from the barrier
func (b *RawBackend) handleRawRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)

	// Preserve pre-existing behavior to decompress if `compressed` is missing
	compressed := true
	if d, ok := data.GetOk("compressed"); ok {
		compressed = d.(bool)
	}

	encoding := data.Get("encoding").(string)
	if encoding != "" && encoding != "base64" {
		return logical.ErrorResponse("invalid encoding %q", encoding), logical.ErrInvalidRequest
	}

	if b.core.recoveryMode {
		b.logger.Info("reading", "path", path)
	}

	storage, _, err := b.storageByPath(ctx, path)
	if err != nil {
		return handleErrorNoReadOnlyForward(err)
	}

	valueBytes, err := storage.Get(ctx, path)
	switch {
	// We match against an error coming from using wrong barrier to read;
	// This happens when we are in a storage space of a namespace that
	// has been discarded from memory due to sealing of its parent.
	case err != nil && strings.HasSuffix(err.Error(), "cipher: message authentication failed"):
		return nil, barrier.ErrNamespaceSealed
	case err != nil:
		return handleErrorNoReadOnlyForward(err)
	case valueBytes == nil:
		return nil, nil
	}

	if compressed {
		// Run this through the decompression helper to see if it's been compressed.
		// If the input contained the compression canary, `decompData` will hold
		// the decompressed data. If the input was not compressed, then `decompData`
		// will be nil.
		decompData, _, err := compressutil.Decompress(valueBytes)
		if err != nil {
			return handleErrorNoReadOnlyForward(err)
		}

		// `decompData` is nil if the input is uncompressed.
		// In that case set it to the original input.
		if decompData != nil {
			valueBytes = decompData
		}
	}

	var value interface{} = string(valueBytes)
	// Golang docs (https://pkg.go.dev/encoding/json#Marshal), []byte encodes as a base64-encoded string
	if encoding == "base64" {
		value = valueBytes
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"value": value,
		},
	}, nil
}

// handleRawWrite is used to write directly to the barrier
func (b *RawBackend) handleRawWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)
	compressionType := ""
	c, compressionTypeOk := data.GetOk("compression_type")
	if compressionTypeOk {
		compressionType = c.(string)
	}

	encoding := data.Get("encoding").(string)
	if encoding != "" && encoding != "base64" {
		return logical.ErrorResponse("invalid encoding %q", encoding), logical.ErrInvalidRequest
	}

	if b.core.recoveryMode {
		b.logger.Info("writing", "path", path)
	}

	v := data.Get("value").(string)
	value := []byte(v)
	if encoding == "base64" {
		var err error
		value, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	storage, allowWrites, err := b.storageByPath(ctx, path)
	if err != nil {
		return handleErrorNoReadOnlyForward(err)
	}

	if !allowWrites {
		return nil, barrier.ErrNamespaceSealed
	}

	if req.Operation == logical.UpdateOperation {
		// Check if this is an existing value with compression applied.
		// If so, use the same compression (or no compression)
		valueBytes, err := storage.Get(ctx, path)
		if err != nil {
			return handleErrorNoReadOnlyForward(err)
		}
		if valueBytes == nil {
			err := "cannot figure out compression type because entry does not exist"
			return logical.ErrorResponse(err), logical.ErrInvalidRequest
		}

		// For cases where DecompressWithCanary errored, treat entry as non-compressed data.
		_, existingCompressionType, _, _ := compressutil.DecompressWithCanary(valueBytes)

		// Ensure compression_type matches existing entries' compression
		// except allow writing non-compressed data over compressed data
		if existingCompressionType != compressionType && compressionType != "" {
			err := "the entry uses a different compression scheme then compression_type"
			return logical.ErrorResponse(err), logical.ErrInvalidRequest
		}

		if !compressionTypeOk {
			compressionType = existingCompressionType
		}
	}

	if compressionType != "" {
		var config *compressutil.CompressionConfig
		switch compressionType {
		case compressutil.CompressionTypeGzip:
			config = &compressutil.CompressionConfig{
				Type:                 compressutil.CompressionTypeGzip,
				GzipCompressionLevel: gzip.BestCompression,
			}
		case compressutil.CompressionTypeSnappy:
			config = &compressutil.CompressionConfig{
				Type: compressutil.CompressionTypeSnappy,
			}
		default:
			err := fmt.Sprintf("invalid compression type %q", compressionType)
			return logical.ErrorResponse(err), logical.ErrInvalidRequest
		}

		var err error
		value, err = compressutil.Compress(value, config)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	if err := storage.Put(ctx, path, value); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return nil, nil
}

// handleRawDelete is used to delete directly from the barrier
func (b *RawBackend) handleRawDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)

	if b.core.recoveryMode {
		b.logger.Info("deleting", "path", path)
	}

	barrier, _, err := b.storageByPath(ctx, path)
	if err != nil {
		return handleErrorNoReadOnlyForward(err)
	}

	if err := barrier.Delete(ctx, path); err != nil {
		return handleErrorNoReadOnlyForward(err)
	}
	return nil, nil
}

// handleRawList is used to list directly from the barrier
func (b *RawBackend) handleRawList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := data.Get("path").(string)
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if b.core.recoveryMode {
		b.logger.Info("listing", "path", path)
	}

	barrier, _, err := b.storageByPath(ctx, path)
	if err != nil {
		return handleErrorNoReadOnlyForward(err)
	}

	keys, err := barrier.ListPage(ctx, path, after, limit)
	if err != nil {
		return handleErrorNoReadOnlyForward(err)
	}
	return logical.ListResponse(keys), nil
}

// existenceCheck checks if entry exists, used in handleRawWrite for update or create operations
func (b *RawBackend) existenceCheck(ctx context.Context, request *logical.Request, data *framework.FieldData) (bool, error) {
	path := data.Get("path").(string)

	storage, allowWrites, err := b.storageByPath(ctx, path)
	if err != nil {
		return false, err
	}

	if !allowWrites {
		return false, barrier.ErrNamespaceSealed
	}

	entry, err := storage.Get(ctx, path)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *RawBackend) rawPaths(prefix string) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: prefix + "(raw/?$|raw/(?P<path>.+))",

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type: framework.TypeString,
				},
				"value": {
					Type: framework.TypeString,
				},
				"compressed": {
					Type: framework.TypeBool,
				},
				"encoding": {
					Type: framework.TypeString,
				},
				"compression_type": {
					Type: framework.TypeString,
				},
				"after": {
					Type:        framework.TypeString,
					Description: `Optional entry to list begin listing after, not required to exist. Only used in list operations.`,
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: `Optional number of entries to return; defaults to all entries. Only used in list operations.`,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRawRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "raw",
						OperationVerb:   "read",
						OperationSuffix: "|path",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"value": {
									Type:     framework.TypeString,
									Required: true,
								},
							},
						}},
					},
					Summary: "Read the value of the key at the given path.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRawWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "raw",
						OperationVerb:   "write",
						OperationSuffix: "|path",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
						}},
					},
					Summary: "Update the value of the key at the given path.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleRawWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "raw",
						OperationVerb:   "write",
						OperationSuffix: "|path",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
						}},
					},
					Summary: "Create a key with value at the given path.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRawDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "raw",
						OperationVerb:   "delete",
						OperationSuffix: "|path",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
						}},
					},
					Summary: "Delete the key with given path.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleRawList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "raw",
						OperationVerb:   "list",
						OperationSuffix: "|path",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
							},
						}},
					},
					Summary: "Return a list keys for a given path prefix.",
				},
			},

			ExistenceCheck:  b.existenceCheck,
			HelpSynopsis:    strings.TrimSpace(sysHelp["raw"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["raw"][1]),
		},
	}
}
