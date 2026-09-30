// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fairshare

import (
	"io"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
)

type (
	initFn    func()
	cleanupFn func()
)

// dispatcher provides bounded execution of jobs on dedicated Goroutines.
type dispatcher struct {
	onceStop sync.Once
	quit     chan struct{}
	sema     chan struct{}
	logger   log.Logger
	wg       *sync.WaitGroup
}

// dispatch spawns a job to within a Goroutine, with optional initialization and
// cleanup functions (useful for tracking job progress).
func (d *dispatcher) dispatch(job Job, init initFn, cleanup cleanupFn) {
	select {
	// Acquire a semaphore ticket.
	case d.sema <- struct{}{}:
		d.wg.Go(func() {
			// Release the semaphore ticket once done.
			defer func() { <-d.sema }()
			// Execute the job, calling any hooks.
			if init != nil {
				init()
			}
			if err := job.Execute(); err != nil {
				job.OnFailure(err)
			}
			if cleanup != nil {
				cleanup()
			}
		})
	case <-d.quit:
		d.logger.Info("shutting down during dispatch")
		return
	}
}

// stop stops the dispatcher, waiting for all Goroutines to exit.
func (d *dispatcher) stop() {
	d.onceStop.Do(func() {
		d.logger.Trace("terminating dispatcher")
		close(d.quit)
		d.wg.Wait()
	})
}

// newDispatcher creates a new dispatcher object.
func newDispatcher(maxWorkers int, l log.Logger) *dispatcher {
	if l == nil {
		l = logging.NewVaultLoggerWithWriter(io.Discard, log.NoLevel)
	}
	if maxWorkers <= 0 {
		maxWorkers = 1
		l.Warn("must have 1 or more workers. setting number of workers to 1")
	}

	var wg sync.WaitGroup
	d := dispatcher{
		quit:   make(chan struct{}),
		sema:   make(chan struct{}, maxWorkers),
		logger: l,
		wg:     &wg,
	}

	return &d
}
