// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package bolt holds stubs for github.com/boltdb/bolt functionality required
// by github.com/hashicorp/raft-boltdb/v2. Bolt is unmaintained and a dependency
// on it would reduce OpenBao's platform support (namely, we would have to
// drop riscv64). raft-boltdb depends on the old bolt package only to provide a
// function (MigrateToV2) to migrate to bbolt, which OpenBao does not use.
package bolt

import (
	"errors"
	"os"
	"time"
)

var err = errors.New("unimplemented")

type Options struct {
	ReadOnly bool
	Timeout  time.Duration
}

type (
	DB     struct{}
	Tx     struct{}
	Bucket struct{}
)

func Open(string, os.FileMode, *Options) (*DB, error)    { return nil, err }
func (*DB) Begin(bool) (*Tx, error)                      { return nil, err }
func (*Tx) Rollback() error                              { return err }
func (*Tx) Bucket([]byte) *Bucket                        { return &Bucket{} }
func (*Bucket) ForEach(func([]byte, []byte) error) error { return err }
