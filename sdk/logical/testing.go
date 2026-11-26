// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"reflect"
	"time"

	testing "github.com/mitchellh/go-testing-interface"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/stretchr/testify/require"
)

// TestRequest is a helper to create a purely in-memory Request struct.
func TestRequest(t testing.T, op Operation, path string) *Request {
	return &Request{
		Operation:  op,
		Path:       path,
		Data:       make(map[string]any),
		Storage:    new(InmemStorage),
		Connection: &Connection{},
	}
}

// TestStorage is a helper that can be used from unit tests to verify
// the behavior of a Storage impl.
func TestStorage(t testing.T, s Storage) {
	keys, err := s.List(context.Background(), "")
	require.NoError(t, err, "list error")
	if len(keys) > 0 {
		t.Fatalf("should have no keys to start: %#v", keys)
	}

	entry := &StorageEntry{Key: "foo", Value: []byte("bar")}
	require.NoError(t, s.Put(context.Background(), entry), "put error")

	actual, err := s.Get(context.Background(), "foo")
	require.NoError(t, err, "get error")
	if !reflect.DeepEqual(actual, entry) {
		t.Fatalf("wrong value. Expected: %#v\nGot: %#v", entry, actual)
	}

	keys, err = s.List(context.Background(), "")
	require.NoError(t, err, "list error")
	if !reflect.DeepEqual(keys, []string{"foo"}) {
		t.Fatalf("bad keys: %#v", keys)
	}

	require.NoError(t, s.Delete(context.Background(), "foo"), "put error")

	keys, err = s.List(context.Background(), "")
	require.NoError(t, err, "list error")
	if len(keys) > 0 {
		t.Fatalf("should have no keys to start: %#v", keys)
	}
}

func TestSystemView() *StaticSystemView {
	return &StaticSystemView{
		DefaultLeaseTTLVal: time.Hour * 24,
		MaxLeaseTTLVal:     time.Hour * 24 * 2,
		VersionString:      "testVersionString",
	}
}

func TestBackendConfig() *BackendConfig {
	return &BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: TestSystemView(),
		Config: make(map[string]string),
	}
}
