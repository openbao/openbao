// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"math/rand"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	uberAtomic "go.uber.org/atomic"
)

const (
	// DefaultJitterPercent is used if no cache size is specified for NewCache
	DefaultJitterPercent = 20
)

// LatencyInjector is used to add latency into underlying physical requests
type LatencyInjector struct {
	logger        log.Logger
	backend       Backend
	latency       *uberAtomic.Duration
	jitterPercent int
	randomLock    *sync.Mutex
	random        *rand.Rand
}

// Verify LatencyInjector satisfies the correct interfaces
var (
	_ Backend = (*LatencyInjector)(nil)
)

// NewLatencyInjector returns a wrapped physical backend to simulate latency
func NewLatencyInjector(b Backend, latency time.Duration, jitter int, logger log.Logger) *LatencyInjector {
	if jitter < 0 || jitter > 100 {
		jitter = DefaultJitterPercent
	}
	logger.Info("creating latency injector")

	return &LatencyInjector{
		logger:        logger,
		backend:       b,
		latency:       uberAtomic.NewDuration(latency),
		jitterPercent: jitter,
		randomLock:    new(sync.Mutex),
		random:        rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
	}
}

func (l *LatencyInjector) SetLatency(latency time.Duration) {
	l.logger.Info("Changing backend latency", "latency", latency)
	l.latency.Store(latency)
}

func (l *LatencyInjector) addLatency() {
	// Calculate a value between 1 +- jitter%
	percent := 100
	if l.jitterPercent > 0 {
		min := 100 - l.jitterPercent
		max := 100 + l.jitterPercent
		l.randomLock.Lock()
		percent = l.random.Intn(max-min) + min
		l.randomLock.Unlock()
	}
	latencyDuration := time.Duration(int(l.latency.Load()) * percent / 100)
	time.Sleep(latencyDuration)
}

// Put is a latent put request
func (l *LatencyInjector) Put(ctx context.Context, entry *Entry) error {
	l.addLatency()
	return l.backend.Put(ctx, entry)
}

// Get is a latent get request
func (l *LatencyInjector) Get(ctx context.Context, key string) (*Entry, error) {
	l.addLatency()
	return l.backend.Get(ctx, key)
}

// Delete is a latent delete request
func (l *LatencyInjector) Delete(ctx context.Context, key string) error {
	l.addLatency()
	return l.backend.Delete(ctx, key)
}

// List is a latent list request
func (l *LatencyInjector) List(ctx context.Context, prefix string) ([]string, error) {
	l.addLatency()
	return l.backend.List(ctx, prefix)
}

// ListPage is a latent paginated list request
func (l *LatencyInjector) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	l.addLatency()
	return l.backend.ListPage(ctx, prefix, after, limit)
}
