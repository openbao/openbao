package vault

import (
	"context"
	"errors"
	"time"
)

// atomicContext is a struct to bind together a context (interface) and its
// cancel function in a single package to help with atomic.Pointer operations.
// Notably from the CancelFunc docs, it is safe to call in multiple contexts
// simultaneously and any subsequent calls will be ignored. These functions
// are written so that if c.activeContext.Load() is called and there is no
// active context, we should mostly behave like a cancelled context.
type atomicContext struct {
	ctx      context.Context
	canceler context.CancelFunc
}

var _ context.Context = &atomicContext{}

func NewAtomicContext(ctx context.Context, cancel context.CancelFunc) *atomicContext {
	return &atomicContext{
		ctx:      ctx,
		canceler: cancel,
	}
}

func (a *atomicContext) IsNil() bool {
	return a == nil || a.ctx == nil
}

func (a *atomicContext) Canceler() context.CancelFunc {
	if a.IsNil() || a.canceler == nil {
		return func() {}
	}

	return a.canceler
}

func (a *atomicContext) Deadline() (time.Time, bool) {
	if a.IsNil() {
		return time.Time{}, false
	}

	return a.ctx.Deadline()
}

func (a *atomicContext) Done() <-chan struct{} {
	if a.IsNil() {
		// This must return a closed channel per documentation on Done to
		// behave like a cancelled context.
		ret := make(chan struct{})
		close(ret)
		return ret
	}

	return a.ctx.Done()
}

func (a *atomicContext) Err() error {
	if a.IsNil() {
		return errors.New("no active context")
	}

	return a.ctx.Err()
}

func (a *atomicContext) Value(key any) any {
	if a.IsNil() {
		return nil
	}

	return a.ctx.Value(key)
}
