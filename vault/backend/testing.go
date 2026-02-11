// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type RouterTestHandlerFunc func(context.Context, *logical.Request) (*logical.Response, error)

type Noop struct {
	sync.Mutex

	Root            []string
	Login           []string
	Paths           []string
	Requests        []*logical.Request
	Response        *logical.Response
	RequestHandler  RouterTestHandlerFunc
	Invalidations   []string
	DefaultLeaseTTL time.Duration
	MaxLeaseTTL     time.Duration
	BackendType     logical.BackendType

	RollbackErrs bool
}

func NoopBackendFactory(_ context.Context, _ *logical.BackendConfig) (logical.Backend, error) {
	return &Noop{}, nil
}

func NoopBackendRollbackErrFactory(_ context.Context, _ *logical.BackendConfig) (logical.Backend, error) {
	return &Noop{RollbackErrs: true}, nil
}

func (n *Noop) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if req.TokenEntry() != nil {
		panic("got a non-nil TokenEntry")
	}

	if n.RollbackErrs && req.Operation == "rollback" {
		return nil, errors.New("no-op backend rollback has erred out")
	}

	var err error
	resp := n.Response
	if n.RequestHandler != nil {
		resp, err = n.RequestHandler(ctx, req)
	}

	n.Lock()
	defer n.Unlock()

	requestCopy := *req
	n.Paths = append(n.Paths, req.Path)
	n.Requests = append(n.Requests, &requestCopy)
	if req.Storage == nil {
		return nil, errors.New("missing view")
	}

	if req.Path == "panic" {
		panic("as you command")
	}

	return resp, err
}

func (n *Noop) HandleExistenceCheck(ctx context.Context, req *logical.Request) (bool, bool, error) {
	return false, false, nil
}

func (n *Noop) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Root:            n.Root,
		Unauthenticated: n.Login,
	}
}

func (n *Noop) System() logical.SystemView {
	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 32
	if n.DefaultLeaseTTL > 0 {
		defaultLeaseTTLVal = n.DefaultLeaseTTL
	}

	if n.MaxLeaseTTL > 0 {
		maxLeaseTTLVal = n.MaxLeaseTTL
	}

	return logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLVal,
		MaxLeaseTTLVal:     maxLeaseTTLVal,
	}
}

func (n *Noop) Cleanup(ctx context.Context) {
	// noop
}

func (n *Noop) InvalidateKey(ctx context.Context, k string) {
	n.Invalidations = append(n.Invalidations, k)
}

func (n *Noop) Setup(ctx context.Context, config *logical.BackendConfig) error {
	return nil
}

func (n *Noop) Logger() log.Logger {
	return log.NewNullLogger()
}

func (n *Noop) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	return nil
}

func (n *Noop) Type() logical.BackendType {
	if n.BackendType == logical.TypeUnknown {
		return logical.TypeLogical
	}
	return n.BackendType
}

// InitializableBackend is a backend that knows whether it has been initialized
// properly.
type InitializableBackend struct {
	*Noop
	IsInitialized bool
}

func (b *InitializableBackend) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	if b.IsInitialized {
		return errors.New("already initialized")
	}

	// do a dummy write, to prove that the storage is not readonly
	entry := &logical.StorageEntry{
		Key:   "initialize/zork",
		Value: []byte("quux"),
	}
	err := req.Storage.Put(ctx, entry)
	if err != nil {
		return err
	}

	b.IsInitialized = true
	return nil
}
