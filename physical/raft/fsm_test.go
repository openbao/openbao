// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"fmt"
	"math/rand"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func getFSM(t testing.TB) *FSM {
	raftDir := t.TempDir()
	t.Logf("raft dir: %s", raftDir)

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "raft",
		Level: hclog.Trace,
	})

	fsm, err := NewFSM(raftDir, "", logger)
	if err != nil {
		t.Fatal(err)
	}

	return fsm
}

func TestFSM_Batching(t *testing.T) {
	t.Parallel()
	fsm := getFSM(t)

	var index uint64
	var term uint64 = 1

	var hookCallCount atomic.Uint64
	fsm.hookInvalidate(func(key ...string) {
		hookCallCount.Add(uint64(len(key)))
	})

	getLog := func(i uint64) (int, *raft.Log) {
		if rand.Intn(10) >= 8 {
			term += 1
			return 0, &raft.Log{
				Index: i,
				Term:  term,
				Type:  raft.LogConfiguration,
				Data: raft.EncodeConfiguration(raft.Configuration{
					Servers: []raft.Server{
						{
							Address: "test",
							ID:      "test",
						},
					},
				}),
			}
		}

		command := &LogData{
			Operations: make([]*LogOperation, rand.Intn(10)),
		}

		for j := range command.Operations {
			command.Operations[j] = &LogOperation{
				OpType: putOp,
				Key:    fmt.Sprintf("key-%d-%d", i, j),
				Value:  fmt.Appendf(nil, "value-%d-%d", i, j),
			}
		}
		commandBytes, err := proto.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		return len(command.Operations), &raft.Log{
			Index: i,
			Term:  term,
			Type:  raft.LogCommand,
			Data:  commandBytes,
		}
	}

	totalKeys := 0
	for range 100 {
		batchSize := rand.Intn(64)
		batch := make([]*raft.Log, batchSize)
		for j := range batchSize {
			var keys int
			index++
			keys, batch[j] = getLog(index)
			totalKeys += keys
		}

		resp := fsm.ApplyBatch(batch)
		if len(resp) != batchSize {
			t.Fatalf("incorrect response length: got %d expected %d", len(resp), batchSize)
		}

		for _, r := range resp {
			if _, ok := r.(*FSMApplyResponse); !ok {
				t.Fatal("bad response type")
			}
		}
	}

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.EqualValues(collect, totalKeys, hookCallCount.Load())
	}, time.Second, time.Millisecond)

	keys, err := fsm.List(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != totalKeys {
		t.Fatalf("incorrect number of keys: got %d expected %d", len(keys), totalKeys)
	}

	latestIndex, latestConfig := fsm.LatestState()
	if latestIndex.Index != index {
		t.Fatalf("bad latest index: got %d expected %d", latestIndex.Index, index)
	}
	if latestIndex.Term != term {
		t.Fatalf("bad latest term: got %d expected %d", latestIndex.Term, term)
	}

	if latestConfig == nil && term > 1 {
		t.Fatal("config wasn't updated")
	}
}

func TestFSM_List(t *testing.T) {
	t.Parallel()
	fsm := getFSM(t)

	ctx := t.Context()
	count := 100
	keys := rand.Perm(count)
	var sorted []string
	for _, k := range keys {
		err := fsm.Put(ctx, &physical.Entry{Key: fmt.Sprintf("foo/%d/bar", k)})
		if err != nil {
			t.Fatal(err)
		}
		err = fsm.Put(ctx, &physical.Entry{Key: fmt.Sprintf("foo/%d/baz", k)})
		if err != nil {
			t.Fatal(err)
		}
		sorted = append(sorted, fmt.Sprintf("%d/", k))
	}
	sort.Strings(sorted)

	got, err := fsm.List(ctx, "foo/")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if diff := deep.Equal(sorted, got); len(diff) > 0 {
		t.Fatal(diff)
	}
}
