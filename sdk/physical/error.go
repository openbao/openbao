// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
)

const (
	// DefaultErrorPercent is used to determin how often we error
	DefaultErrorPercent = 20
)

// ErrorInjector is used to add errors into underlying physical requests
type ErrorInjector interface {
	Backend
	SetErrorPercentage(int)
}

type errorInjector struct {
	backend      Backend
	errorPercent int
	randomLock   *sync.Mutex
	random       *rand.Rand
}

var _ ErrorInjector = &errorInjector{}

type transactionalErrorInjector struct {
	*errorInjector
}

var (
	_ ErrorInjector        = &transactionalErrorInjector{}
	_ TransactionalBackend = &transactionalErrorInjector{}
)

type errorInjectorTransaction struct {
	*errorInjector
}

var (
	_ ErrorInjector = &errorInjectorTransaction{}
	_ Transaction   = &errorInjectorTransaction{}
)

// NewErrorInjector returns a wrapped physical backend to inject error
func NewErrorInjector(b Backend, errorPercent int, logger log.Logger) ErrorInjector {
	if errorPercent < 0 || errorPercent > 100 {
		errorPercent = DefaultErrorPercent
	}

	if logger != nil {
		logger.Info("creating error injector")
	}

	e := &errorInjector{
		backend:      b,
		errorPercent: errorPercent,
		randomLock:   new(sync.Mutex),
		random:       rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
	}

	if _, ok := b.(TransactionalBackend); ok {
		return &transactionalErrorInjector{
			e,
		}
	}

	return e
}

func (e *errorInjector) SetErrorPercentage(p int) {
	e.errorPercent = p
}

func (e *errorInjector) addError() error {
	e.randomLock.Lock()
	roll := e.random.Intn(100)
	e.randomLock.Unlock()
	if roll < e.errorPercent {
		return errors.New("random error")
	}

	return nil
}

func (e *errorInjector) Put(ctx context.Context, entry *Entry) error {
	if err := e.addError(); err != nil {
		return err
	}
	return e.backend.Put(ctx, entry)
}

func (e *errorInjector) Get(ctx context.Context, key string) (*Entry, error) {
	if err := e.addError(); err != nil {
		return nil, err
	}
	return e.backend.Get(ctx, key)
}

func (e *errorInjector) Delete(ctx context.Context, key string) error {
	if err := e.addError(); err != nil {
		return err
	}
	return e.backend.Delete(ctx, key)
}

func (e *errorInjector) List(ctx context.Context, prefix string) ([]string, error) {
	if err := e.addError(); err != nil {
		return nil, err
	}
	return e.backend.List(ctx, prefix)
}

func (e *errorInjector) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	if err := e.addError(); err != nil {
		return nil, err
	}
	return e.backend.ListPage(ctx, prefix, after, limit)
}

func (e *transactionalErrorInjector) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	txn, err := e.backend.(TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	ret := NewErrorInjector(txn, e.errorPercent, nil)
	return &errorInjectorTransaction{ret.(*errorInjector)}, nil
}

func (e *transactionalErrorInjector) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := e.backend.(TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	ret := NewErrorInjector(txn, e.errorPercent, nil)
	return &errorInjectorTransaction{ret.(*errorInjector)}, nil
}

func (e *errorInjectorTransaction) Commit(ctx context.Context) error {
	return e.backend.(Transaction).Commit(ctx)
}

func (e *errorInjectorTransaction) Rollback(ctx context.Context) error {
	return e.backend.(Transaction).Rollback(ctx)
}
