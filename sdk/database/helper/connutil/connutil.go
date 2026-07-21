// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connutil

import (
	"context"
	"errors"
	"sync"
)

var ErrNotInitialized = errors.New("connection has not been initialized")

// ConnectionProducer can be used as an embedded interface in the Database
// definition. It implements the methods dealing with individual database
// connections and is used in all the builtin database types.
type ConnectionProducer interface {
	Close() error
	Init(context.Context, map[string]any, bool) (map[string]any, error)
	Connection(context.Context) (any, error)

	sync.Locker
}
