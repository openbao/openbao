// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package watch

import (
	"fmt"
	"sync"
	"time"

	dep "github.com/hashicorp/consul-template/dependency"
)

// TestDep is a special dependency that does not actually speaks to a server.
type TestDep struct {
	name string
}

func (d *TestDep) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	time.Sleep(time.Millisecond)
	data := "this is some data"
	rm := &dep.ResponseMetadata{LastIndex: 1}
	return data, rm, nil
}

func (d *TestDep) CanShare() bool {
	return true
}

func (d *TestDep) String() string {
	return fmt.Sprintf("test_dep(%s)", d.name)
}

func (d *TestDep) Stop() {}

func (d *TestDep) Type() dep.Type {
	return dep.TypeLocal
}

// TestDepStale is a special dependency that can be used to test what happens when
// stale data is permitted.
type TestDepStale struct {
	name string
}

// Fetch is used to implement the dependency interface.
func (d *TestDepStale) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	time.Sleep(time.Millisecond)

	if opts == nil {
		opts = &dep.QueryOptions{}
	}

	if opts.AllowStale {
		data := "this is some stale data"
		rm := &dep.ResponseMetadata{LastIndex: 1, LastContact: 50 * time.Millisecond}
		return data, rm, nil
	}

	data := "this is some fresh data"
	rm := &dep.ResponseMetadata{LastIndex: 1}
	return data, rm, nil
}

func (d *TestDepStale) CanShare() bool {
	return true
}

func (d *TestDepStale) String() string {
	return fmt.Sprintf("test_dep_stale(%s)", d.name)
}

func (d *TestDepStale) Stop() {}

func (d *TestDepStale) Type() dep.Type {
	return dep.TypeLocal
}

// TestDepFetchError is a special dependency that returns an error while fetching.
type TestDepFetchError struct {
	name string
}

func (d *TestDepFetchError) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	time.Sleep(time.Millisecond)
	return nil, nil, fmt.Errorf("failed to contact server")
}

func (d *TestDepFetchError) CanShare() bool {
	return true
}

func (d *TestDepFetchError) String() string {
	return fmt.Sprintf("test_dep_fetch_error(%s)", d.name)
}

func (d *TestDepFetchError) Stop() {}

func (d *TestDepFetchError) Type() dep.Type {
	return dep.TypeLocal
}

var _ dep.Dependency = (*TestDepSameIndex)(nil)

type TestDepSameIndex struct{}

func (d *TestDepSameIndex) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	meta := &dep.ResponseMetadata{LastIndex: 100}
	return nil, meta, nil
}

func (d *TestDepSameIndex) CanShare() bool {
	return true
}

func (d *TestDepSameIndex) Stop() {}

func (d *TestDepSameIndex) String() string {
	return "test_dep_same_index"
}

func (d *TestDepSameIndex) Type() dep.Type {
	return dep.TypeLocal
}

// TestDepRetry is a special dependency that errors on the first fetch and
// succeeds on subsequent fetches.
type TestDepRetry struct {
	sync.Mutex
	name    string
	retried bool
}

func (d *TestDepRetry) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	time.Sleep(time.Millisecond)

	d.Lock()
	defer d.Unlock()

	if d.retried {
		data := "this is some data"
		rm := &dep.ResponseMetadata{LastIndex: 1}
		return data, rm, nil
	}

	d.retried = true
	return nil, nil, fmt.Errorf("failed to contact server (try again)")
}

func (d *TestDepRetry) CanShare() bool {
	return true
}

func (d *TestDepRetry) String() string {
	return fmt.Sprintf("test_dep_retry(%s)", d.name)
}

func (d *TestDepRetry) Stop() {}

func (d *TestDepRetry) Type() dep.Type {
	return dep.TypeLocal
}

// TestDepBlock is a dependency that think's its blocking
type TestDepBlock struct {
	TestDep
}

func (d *TestDepBlock) Fetch(clients *dep.ClientSet, opts *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	meta := &dep.ResponseMetadata{LastIndex: 100, BlockOnNil: true}
	return nil, meta, nil
}

func (d *TestDepBlock) String() string {
	return "test_dep_block"
}
