// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

var (
	errMissingStorage   = errors.New("missing storage implementation: this method should not be called during plugin Setup, but only during and after Initialize")
	errNotTransactional = errors.New("underlying storage implementation does not support transactions; refusing to call transaction method")
)

func newGRPCStorageClient(ctx context.Context, conn *grpc.ClientConn) (logical.Storage, error) {
	client := pb.NewStorageClient(conn)

	// Not every server will support transactional storage: if plugins built
	// with OpenBao's SDK run against an upstream HashiCorp Vault server,
	// we'll get an Unimplemented error that we'll want to handle nicely by
	// not indicating support for transactions.
	reply, err := client.IsTransactional(ctx, &pb.Empty{})
	if err != nil && !strings.Contains(err.Error(), "Unimplemented") && !strings.Contains(err.Error(), errMissingStorage.Error()) {
		return nil, fmt.Errorf("error identifying transactional status of backend: %w", err)
	}

	gsc := &GRPCStorageClient{
		client: client,
	}

	if err == nil && reply != nil && reply.Transactional {
		return &GRPCTransactionalStorageClient{
			*gsc,
		}, nil
	}

	return gsc, nil
}

// GRPCStorageClient is an implementation of logical.Storage that communicates
// over RPC.
type GRPCStorageClient struct {
	client pb.StorageClient
	txn    string
}

var _ logical.Storage = &GRPCStorageClient{}

type GRPCTransactionalStorageClient struct {
	GRPCStorageClient
}

var _ logical.Transactional = &GRPCTransactionalStorageClient{}

type GRPCStorageClientTransaction struct {
	GRPCStorageClient
}

func (s *GRPCStorageClient) List(ctx context.Context, prefix string) ([]string, error) {
	reply, err := s.client.List(ctx, &pb.StorageListArgs{
		Prefix: prefix,
		Txn:    s.txn,
	}, largeMsgGRPCCallOpts...)
	if err != nil {
		return []string{}, err
	}
	if reply.Err != "" {
		return reply.Keys, errors.New(reply.Err)
	}
	return reply.Keys, nil
}

func (s *GRPCStorageClient) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	reply, err := s.client.ListPage(ctx, &pb.StorageListPageArgs{
		Prefix: prefix,
		After:  after,
		Limit:  int32(limit),
		Txn:    s.txn,
	}, largeMsgGRPCCallOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "Unimplemented") {
			// Implement ListPage(...) manually. Assume the results are
			// already sorted from the storage backend.
			results, listErr := s.List(ctx, prefix)
			if listErr != nil {
				return nil, fmt.Errorf("failed to re-call List(...) from ListPage(...): %w\n\toriginal: %v", listErr, err)
			}

			if after != "" {
				idx := sort.SearchStrings(results, after)
				if idx < len(results) && results[idx] == after {
					idx += 1
				}
				results = results[idx:]
			}

			if limit > 0 {
				if limit > len(results) {
					limit = len(results)
				}
				results = results[0:limit]
			}

			return results, nil
		}

		return []string{}, err
	}
	if reply.Err != "" {
		return reply.Keys, errors.New(reply.Err)
	}
	return reply.Keys, nil
}

func (s *GRPCStorageClient) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	reply, err := s.client.Get(ctx, &pb.StorageGetArgs{
		Key: key,
		Txn: s.txn,
	}, largeMsgGRPCCallOpts...)
	if err != nil {
		return nil, err
	}
	if reply.Err != "" {
		return nil, errors.New(reply.Err)
	}
	return pb.ProtoStorageEntryToLogicalStorageEntry(reply.Entry), nil
}

func (s *GRPCStorageClient) Put(ctx context.Context, entry *logical.StorageEntry) error {
	reply, err := s.client.Put(ctx, &pb.StoragePutArgs{
		Entry: pb.LogicalStorageEntryToProtoStorageEntry(entry),
		Txn:   s.txn,
	}, largeMsgGRPCCallOpts...)
	if err != nil {
		return err
	}
	if reply.Err != "" {
		return errors.New(reply.Err)
	}
	return nil
}

func (s *GRPCStorageClient) Delete(ctx context.Context, key string) error {
	reply, err := s.client.Delete(ctx, &pb.StorageDeleteArgs{
		Key: key,
		Txn: s.txn,
	})
	if err != nil {
		return err
	}
	if reply.Err != "" {
		return errors.New(reply.Err)
	}
	return nil
}

func (s *GRPCTransactionalStorageClient) BeginReadOnlyTx(ctx context.Context) (logical.Transaction, error) {
	reply, err := s.client.BeginReadOnlyTx(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}

	return &GRPCStorageClientTransaction{
		GRPCStorageClient{
			client: s.client,
			txn:    reply.Txn,
		},
	}, nil
}

func (s *GRPCTransactionalStorageClient) BeginTx(ctx context.Context) (logical.Transaction, error) {
	reply, err := s.client.BeginTx(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}

	return &GRPCStorageClientTransaction{
		GRPCStorageClient{
			client: s.client,
			txn:    reply.Txn,
		},
	}, nil
}

func (s *GRPCStorageClientTransaction) Commit(ctx context.Context) error {
	reply, err := s.client.Commit(ctx, &pb.StorageCommitTxArgs{
		Txn: s.txn,
	})
	if err != nil {
		return err
	}

	if reply.Err != "" {
		return errors.New(reply.Err)
	}

	return nil
}

func (s *GRPCStorageClientTransaction) Rollback(ctx context.Context) error {
	reply, err := s.client.Rollback(ctx, &pb.StorageRollbackTxArgs{
		Txn: s.txn,
	})
	if err != nil {
		return err
	}

	if reply.Err != "" {
		return errors.New(reply.Err)
	}

	return nil
}

// GRPCStorageServer is a net/rpc compatible structure for serving
type GRPCStorageServer struct {
	pb.UnimplementedStorageServer
	impl logical.Storage

	// txns may be concurrently accessed so make sure we use a
	// concurrency-safe data structure to store them.
	txns sync.Map
}

func (s *GRPCStorageServer) List(ctx context.Context, args *pb.StorageListArgs) (*pb.StorageListReply, error) {
	impl := s.impl
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.Load(args.Txn)
		if ok {
			impl = implRaw.(logical.Storage)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	keys, err := impl.List(ctx, args.Prefix)
	return &pb.StorageListReply{
		Keys: keys,
		Err:  pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) ListPage(ctx context.Context, args *pb.StorageListPageArgs) (*pb.StorageListReply, error) {
	impl := s.impl
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.Load(args.Txn)
		if ok {
			impl = implRaw.(logical.Storage)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	keys, err := impl.ListPage(ctx, args.Prefix, args.After, int(args.Limit))
	return &pb.StorageListReply{
		Keys: keys,
		Err:  pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) Get(ctx context.Context, args *pb.StorageGetArgs) (*pb.StorageGetReply, error) {
	impl := s.impl
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.Load(args.Txn)
		if ok {
			impl = implRaw.(logical.Storage)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	storageEntry, err := impl.Get(ctx, args.Key)
	if storageEntry == nil {
		return &pb.StorageGetReply{
			Entry: nil,
			Err:   pb.ErrToString(err),
		}, nil
	}
	return &pb.StorageGetReply{
		Entry: pb.LogicalStorageEntryToProtoStorageEntry(storageEntry),
		Err:   pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) Put(ctx context.Context, args *pb.StoragePutArgs) (*pb.StoragePutReply, error) {
	impl := s.impl
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.Load(args.Txn)
		if ok {
			impl = implRaw.(logical.Storage)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	err := impl.Put(ctx, pb.ProtoStorageEntryToLogicalStorageEntry(args.Entry))
	return &pb.StoragePutReply{
		Err: pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) Delete(ctx context.Context, args *pb.StorageDeleteArgs) (*pb.StorageDeleteReply, error) {
	impl := s.impl
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.Load(args.Txn)
		if ok {
			impl = implRaw.(logical.Storage)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	err := impl.Delete(ctx, args.Key)
	return &pb.StorageDeleteReply{
		Err: pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) IsTransactional(ctx context.Context, args *pb.Empty) (*pb.StorageIsTransactionalReply, error) {
	if s.impl == nil {
		return nil, errMissingStorage
	}

	_, transactional := s.impl.(logical.Transactional)
	return &pb.StorageIsTransactionalReply{
		Transactional: transactional,
	}, nil
}

func (s *GRPCStorageServer) BeginReadOnlyTx(ctx context.Context, args *pb.Empty) (*pb.StorageBeginTxReply, error) {
	if s.impl == nil {
		return nil, errMissingStorage
	}

	tImpl, ok := s.impl.(logical.Transactional)
	if !ok {
		return nil, errNotTransactional
	}

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	txn, err := tImpl.BeginReadOnlyTx(ctx)
	if err != nil {
		return &pb.StorageBeginTxReply{
			Err: pb.ErrToString(err),
		}, nil
	}

	s.txns.Store(uuid, txn)
	return &pb.StorageBeginTxReply{
		Txn: uuid,
	}, nil
}

func (s *GRPCStorageServer) BeginTx(ctx context.Context, args *pb.Empty) (*pb.StorageBeginTxReply, error) {
	if s.impl == nil {
		return nil, errMissingStorage
	}

	tImpl, ok := s.impl.(logical.Transactional)
	if !ok {
		return nil, errNotTransactional
	}

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	txn, err := tImpl.BeginTx(ctx)
	if err != nil {
		return &pb.StorageBeginTxReply{
			Err: pb.ErrToString(err),
		}, nil
	}

	s.txns.Store(uuid, txn)
	return &pb.StorageBeginTxReply{
		Txn: uuid,
	}, nil
}

func (s *GRPCStorageServer) Commit(ctx context.Context, args *pb.StorageCommitTxArgs) (*pb.StorageCommitTxReply, error) {
	var impl logical.Transaction
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.LoadAndDelete(args.Txn)
		if ok {
			impl = implRaw.(logical.Transaction)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	err := impl.Commit(ctx)
	return &pb.StorageCommitTxReply{
		Err: pb.ErrToString(err),
	}, nil
}

func (s *GRPCStorageServer) Rollback(ctx context.Context, args *pb.StorageRollbackTxArgs) (*pb.StorageRollbackTxReply, error) {
	var impl logical.Transaction
	if args != nil && args.Txn != "" {
		implRaw, ok := s.txns.LoadAndDelete(args.Txn)
		if ok {
			impl = implRaw.(logical.Transaction)
		}
	}

	if impl == nil {
		return nil, errMissingStorage
	}

	err := impl.Rollback(ctx)
	return &pb.StorageRollbackTxReply{
		Err: pb.ErrToString(err),
	}, nil
}

// NOOPStorage is used to deny access to the storage interface while running a
// backend plugin in metadata mode.
type NOOPStorage struct{}

func (s *NOOPStorage) List(_ context.Context, prefix string) ([]string, error) {
	return []string{}, nil
}

func (s *NOOPStorage) ListPage(_ context.Context, prefix string, after string, limit int) ([]string, error) {
	return []string{}, nil
}

func (s *NOOPStorage) Get(_ context.Context, key string) (*logical.StorageEntry, error) {
	return nil, nil
}

func (s *NOOPStorage) Put(_ context.Context, entry *logical.StorageEntry) error {
	return nil
}

func (s *NOOPStorage) Delete(_ context.Context, key string) error {
	return nil
}
