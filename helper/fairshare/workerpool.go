// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fairshare

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

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

// wrappedJob tracks a job with its init/cleanup callbacks
type wrappedJob struct {
	job     Job
	init    initFn
	cleanup cleanupFn
}

// syncOnce cleanup ensures cleanup is called exactly once
type syncOnceCleanup struct {
	once    sync.Once
	cleanup cleanupFn
}

func (s *syncOnceCleanup) Do() {
	s.once.Do(func() {
		if s.cleanup != nil {
			s.cleanup()
		}
	})
}

// worker represents a single worker in a pool
type worker struct {
	name   string
	jobCh  <-chan wrappedJob
	quit   chan struct{}
	logger log.Logger
	wg     *sync.WaitGroup
}

func (w *worker) start() {
	w.wg.Add(1)
	go func() {
		for {
			select {
			case <-w.quit:
				w.wg.Done()
				return
			case wJob, ok := <-w.jobCh:
				if !ok {
					w.wg.Done()
					return
				}
				cleanupWrapper := &syncOnceCleanup{cleanup: wJob.cleanup}

				if wJob.init != nil {
					wJob.init()
				}

				err := wJob.job.Execute()
				if err != nil {
					wJob.job.OnFailure(err)
				}

				cleanupWrapper.Do()
			}
		}
	}()
}

// dispatcher represents a worker pool with bounded queue and backpressure
type dispatcher struct {
	name       string
	numWorkers int
	workers    []worker
	jobCh      chan wrappedJob
	onceStart  sync.Once
	onceStop   sync.Once
	quit       chan struct{}
	logger     log.Logger
	wg         *sync.WaitGroup

	// Queue metrics for monitoring
	queueDepth    atomic.Int64
	maxQueueDepth atomic.Int64
	dispatches    atomic.Int64
	completed     atomic.Int64
	timeout       atomic.Int64

	// Shutdown state
	stopping atomic.Bool
}

// QueueStats provides metrics about the dispatcher queue
type QueueStats struct {
	QueueDepth    int64
	MaxQueueDepth int64
	Dispatches    int64
	Completed     int64
	Timeouts      int64
	Workers       int
}

// Stats returns current queue statistics
func (d *dispatcher) Stats() QueueStats {
	return QueueStats{
		QueueDepth:    d.queueDepth.Load(),
		MaxQueueDepth: d.maxQueueDepth.Load(),
		Dispatches:    d.dispatches.Load(),
		Completed:     d.completed.Load(),
		Timeouts:      d.timeout.Load(),
		Workers:       d.numWorkers,
	}
}

// newDispatcher creates a dispatcher with bounded queue
// queueSize: max jobs waiting when system is under load (backpressure)
// queueSize=0: unlimited (legacy behavior, uses unbuffered channel)
func newDispatcher(name string, numWorkers int, queueSize int, l log.Logger) *dispatcher {
	d := createDispatcher(name, numWorkers, l)

	if queueSize > 0 {
		d.jobCh = make(chan wrappedJob, queueSize)
	} else {
		d.jobCh = make(chan wrappedJob)
	}

	d.init()

	return d
}

// createDispatcher creates a dispatcher without starting workers
func createDispatcher(name string, numWorkers int, l log.Logger) *dispatcher {
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
		numWorkers: numWorkers,
		workers:    make([]worker, 0),
		jobCh:      make(chan wrappedJob),
		quit:       make(chan struct{}),
		logger:     l,
		wg:         &wg,
	}

	d.logger.Trace("created dispatcher", "name", d.name, "num_workers", d.numWorkers)
	return &d
}

func (d *dispatcher) init() {
	for len(d.workers) < d.numWorkers {
		d.initializeWorker()
	}
	d.logger.Trace("initialized dispatcher", "num_workers", d.numWorkers)
}

func (d *dispatcher) initializeWorker() {
	w := worker{
		name:   fmt.Sprint("worker-", len(d.workers)),
		jobCh:  d.jobCh,
		quit:   d.quit,
		logger: d.logger,
		wg:     d.wg,
	}
	d.workers = append(d.workers, w)
}

func (d *dispatcher) dispatch(job Job, init initFn, cleanup cleanupFn) bool {
	if d.stopping.Load() {
		return false
	}

	wJob := wrappedJob{
		init:    init,
		job:     job,
		cleanup: cleanup,
	}

	d.dispatches.Add(1)
	d.queueDepth.Add(1)

	isUnbuffered := cap(d.jobCh) == 0
	if isUnbuffered {
		select {
		case d.jobCh <- wJob:
			d.queueDepth.Add(-1)
			return true
		case <-d.quit:
			d.queueDepth.Add(-1)
			return false
		}
	}

	select {
	case d.jobCh <- wJob:
		// Job accepted by worker
		currentDepth := d.queueDepth.Add(-1)
		// Track max queue depth
		for {
			max := d.maxQueueDepth.Load()
			if currentDepth <= max {
				break
			}
			if d.maxQueueDepth.CompareAndSwap(max, currentDepth) {
				break
			}
		}
		return true
	case <-d.quit:
		d.queueDepth.Add(-1)
		return false
	default:
		// Queue full - backpressure
		d.queueDepth.Add(-1)
		d.logger.Trace("dispatcher queue full, rejecting job",
			"queue_depth", d.queueDepth.Load(),
			"max_workers", d.numWorkers)
		return false
	}
}

// TryDispatch attempts to dispatch without blocking, for non-critical jobs
func (d *dispatcher) TryDispatch(job Job, init initFn, cleanup cleanupFn) bool {
	return d.dispatch(job, init, cleanup)
}

// dispatchWithTimeout attempts dispatch with timeout for waiting in queue
// timeout=0 means wait indefinitely (legacy behavior)
func (d *dispatcher) dispatchWithTimeout(job Job, init initFn, cleanup cleanupFn, timeout time.Duration) bool {
	if d.stopping.Load() {
		return false
	}

	wJob := wrappedJob{
		init:    init,
		job:     job,
		cleanup: cleanup,
	}

	d.dispatches.Add(1)
	d.queueDepth.Add(1)

	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutCh = time.After(timeout)
	}

	select {
	case d.jobCh <- wJob:
		d.queueDepth.Add(-1)
		return true
	case <-d.quit:
		d.queueDepth.Add(-1)
		return false
	case <-timeoutCh:
		d.queueDepth.Add(-1)
		d.timeout.Add(1)
		d.logger.Trace("dispatch timeout - job rejected")
		return false
	}
}

func (d *dispatcher) start() {
	d.onceStart.Do(func() {
		d.logger.Trace("starting dispatcher", "num_workers", d.numWorkers)
		for _, w := range d.workers {
			worker := w
			worker.start()
		}
	})
}

// stop gracefully stops the dispatcher, waiting for in-flight jobs
func (d *dispatcher) stop() {
	d.onceStop.Do(func() {
		d.logger.Trace("terminating dispatcher")

		// Phase 1: Stop accepting new jobs
		d.stopping.Store(true)

		// Close job channel to signal no more jobs will be accepted
		// Workers will exit after receiving any remaining job
		close(d.jobCh)

		// Phase 2: Wait for workers to finish processing their current job
		d.wg.Wait()

		// Phase 3: Close quit (workers are already gone)
		close(d.quit)
	})
}
