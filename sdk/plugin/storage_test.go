// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

func TestStorage_GRPC_ReturnsErrIfStorageNil(t *testing.T) {
	_, err := new(GRPCStorageServer).Get(context.Background(), nil)
	if err == nil {
		t.Error("Expected error when using server with no impl")
	}
}

func TestStorage_impl(t *testing.T) {
	var _ logical.Storage = new(GRPCStorageClient)
}

func TestStorage_GRPC(t *testing.T) {
	storage := &logical.InmemStorage{}
	client, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		pb.RegisterStorageServer(s, &GRPCStorageServer{
			impl: storage,
		})
	})
	defer client.Close()

	testStorage := &GRPCStorageClient{client: pb.NewStorageClient(client)}

	logical.TestStorage(t, testStorage)
}

func TestStorage_GRPCTransaction(t *testing.T) {
	physical, err := inmem.NewInmem(nil, logging.NewVaultLogger(log.Trace))
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	storage := logical.NewLogicalStorage(physical)

	client, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		pb.RegisterStorageServer(s, &GRPCStorageServer{
			impl: storage,
		})
	})
	defer client.Close()

	testStorage, err := newGRPCStorageClient(context.TODO(), client)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if _, ok := storage.(logical.Transactional); !ok {
		t.Fatal("expected base storage to be transactional but wasn't")
	}

	if _, ok := testStorage.(logical.Transactional); !ok {
		t.Fatal("expected client to be transactional but wasn't")
	}

	logical.TestStorage(t, testStorage)
}
