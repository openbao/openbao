// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/command/agentproxyshared/sink"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
)

func TestSinkServer(t *testing.T) {
	log := logging.NewVaultLogger(hclog.Trace)

	fs1, path1 := testFileSink(t, log)
	defer os.RemoveAll(path1)
	fs2, path2 := testFileSink(t, log)
	defer os.RemoveAll(path2)

	ctx, cancelFunc := context.WithCancel(context.Background())

	ss := sink.NewSinkServer(&sink.SinkServerConfig{
		Logger: log.Named("sink.server"),
	})

	uuidStr, _ := uuid.GenerateUUID()
	in := make(chan string)
	sinks := []*sink.SinkConfig{fs1, fs2}
	errCh := make(chan error)
	go func() {
		errCh <- ss.Run(ctx, in, sinks)
	}()

	// Seed a token
	in <- uuidStr

	// Tell it to shut down and give it time to do so
	timer := time.AfterFunc(3*time.Second, func() {
		cancelFunc()
	})
	defer timer.Stop()

	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{path1, path2} {
		fileBytes, err := os.ReadFile(fmt.Sprintf("%s/token", path))
		if err != nil {
			t.Fatal(err)
		}

		if string(fileBytes) != uuidStr {
			t.Fatalf("expected %s, got %s", uuidStr, string(fileBytes))
		}
	}
}

type badSink struct {
	tryCount atomic.Uint32
	logger   hclog.Logger
}

func (b *badSink) WriteToken(token string) error {
	switch token {
	case "bad":
		b.tryCount.Add(1)
		b.logger.Info("got bad")
		return errors.New("bad")
	case "good":
		b.tryCount.Store(0)
		b.logger.Info("got good")
		return nil
	default:
		return errors.New("unknown case")
	}
}

func TestSinkServerRetry(t *testing.T) {
	log := logging.NewVaultLogger(hclog.Trace)

	b1 := &badSink{logger: log.Named("b1")}
	b2 := &badSink{logger: log.Named("b2")}

	ctx, cancelFunc := context.WithCancel(context.Background())

	ss := sink.NewSinkServer(&sink.SinkServerConfig{
		Logger: log.Named("sink.server"),
	})

	in := make(chan string)
	sinks := []*sink.SinkConfig{{Sink: b1}, {Sink: b2}}
	errCh := make(chan error)
	go func() {
		errCh <- ss.Run(ctx, in, sinks)
	}()

	// Seed a token
	in <- "bad"

	// During this time we should see it retry multiple times
	time.Sleep(10 * time.Second)
	if b1.tryCount.Load() < 2 {
		t.Fatal("bad try count")
	}
	if b2.tryCount.Load() < 2 {
		t.Fatal("bad try count")
	}

	in <- "good"

	time.Sleep(2 * time.Second)
	if b1.tryCount.Load() != 0 {
		t.Fatal("bad try count")
	}
	if b2.tryCount.Load() != 0 {
		t.Fatal("bad try count")
	}

	// Tell it to shut down and give it time to do so
	cancelFunc()
	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}
}
