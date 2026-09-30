// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fairshare

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	log "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
)

// Job is an interface for jobs used with this job manager
type Job interface {
	// Execute performs the work.
	// It should be synchronous if a cleanupFn is provided.
	Execute() error

	// OnFailure handles the error resulting from a failed Execute().
	// It should be synchronous if a cleanupFn is provided.
	OnFailure(err error)
}

type (
	initFn    func()
	cleanupFn func()
)

type wrappedJob struct {
	job     Job
	init    initFn
	cleanup cleanupFn
}

// run executes the job, calling any hooks before and after execution.
func (w *wrappedJob) run() {
	if w.init != nil {
		w.init()
	}

	err := w.job.Execute()
	if err != nil {
		w.job.OnFailure(err)
	}

	if w.cleanup != nil {
		w.cleanup()
	}
}

// dispatcher represents a worker pool
type dispatcher struct {
	name       string
	maxWorkers int
	workers    atomic.Int32
	jobCh      chan wrappedJob
	onceStop   sync.Once
	quit       chan struct{}
	logger     log.Logger
	wg         *sync.WaitGroup
}

// dispatch dispatches a job to the worker pool, with optional initialization
// and cleanup functions (useful for tracking job progress)
func (d *dispatcher) dispatch(job Job, init initFn, cleanup cleanupFn) {
	wJob := wrappedJob{
		init:    init,
		job:     job,
		cleanup: cleanup,
	}

	select {
	case d.jobCh <- wJob:
		return
	case <-d.quit:
		d.logger.Info("shutting down during dispatch")
		return
	default:
		// If we cannot submit our job right away, attempt growing the worker
		// pool and submitting the job as the new worker's initial job.
		if d.tryGrowPool(wJob) {
			return
		}
	}

	// Go back to waiting on channels, without a fallback.
	select {
	case d.jobCh <- wJob:
	case <-d.quit:
		d.logger.Info("shutting down during dispatch")
	}
}

// stop stops the worker pool, waiting for all workers to exit.
func (d *dispatcher) stop() {
	d.onceStop.Do(func() {
		d.logger.Trace("terminating dispatcher")
		close(d.quit)
		d.wg.Wait()
	})
}

// newDispatcher creates a new dispatcher object.
func newDispatcher(name string, numWorkers int, l log.Logger) *dispatcher {
	if l == nil {
		l = logging.NewVaultLoggerWithWriter(io.Discard, log.NoLevel)
	}
	if numWorkers <= 0 {
		numWorkers = 1
		l.Warn("must have 1 or more workers. setting number of workers to 1")
	}

	if name == "" {
		guid, err := uuid.GenerateUUID()
		if err != nil {
			l.Warn("uuid generator failed, using 'no-uuid'", "err", err)
			guid = "no-uuid"
		}

		name = fmt.Sprintf("dispatcher-%s", guid)
	}

	var wg sync.WaitGroup
	d := dispatcher{
		name:       name,
		maxWorkers: numWorkers,
		jobCh:      make(chan wrappedJob),
		quit:       make(chan struct{}),
		logger:     l,
		wg:         &wg,
	}

	d.logger.Trace("created dispatcher", "name", d.name, "num_workers", d.maxWorkers)
	return &d
}

// tryGrowPool adds a new worker to the pool if it has not reached capacity yet
// and hands the given job to the worker as its initial one.
func (d *dispatcher) tryGrowPool(job wrappedJob) bool {
	for {
		n := d.workers.Load()
		if int(n) == d.maxWorkers {
			// Can't grow any further.
			return false
		}
		if d.workers.CompareAndSwap(n, n+1) {
			// We may grow the pool.
			d.startWorker(job)
			return true
		}
	}
}

// startWorker starts a worker goroutine, taking an initial job that created
// demand for the worker, then listening and working until the quit channel is
// closed.
func (d *dispatcher) startWorker(initial wrappedJob) {
	d.wg.Go(func() {
		initial.run()
		for {
			select {
			case <-d.quit:
				return
			case job := <-d.jobCh:
				job.run()
			}
		}
	})
}
