package fairshare

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStress_HighThroughputSustained(t *testing.T) {
	numWorkers := 50
	targetRPS := 10000
	duration := 10 * time.Second

	d := newDispatcher("stress-throughput", numWorkers, newTestLogger("stress-throughput"))
	d.start()

	var dispatched int64
	var completed int64
	var cleanups int64
	var wg sync.WaitGroup

	rpsStopCh := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		interval := time.Second / time.Duration(targetRPS)

		for {
			select {
			case <-rpsStopCh:
				return
			case <-ticker.C:
				close(rpsStopCh)
				return
			default:
				job := &testJob{
					id: "job",
					ex: func(id string) error {
						atomic.AddInt64(&completed, 1)
						time.Sleep(time.Microsecond * 100)
						return nil
					},
					onFail: func(error) {},
				}
				d.dispatch(job,
					func() { atomic.AddInt64(&dispatched, 1) },
					func() { atomic.AddInt64(&cleanups, 1) },
				)
				time.Sleep(interval)
			}
		}
	}()

	wg.Wait()
	time.Sleep(500 * time.Millisecond)

	goroutineCount := runtime.NumGoroutine()
	t.Logf("=== DURING LOAD ===")
	t.Logf("Duration: %v, Target RPS: %d", duration, targetRPS)
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)
	t.Logf("Actual RPS: %.2f", float64(dispatched)/duration.Seconds())
	t.Logf("Goroutines: %d", goroutineCount)

	time.Sleep(1 * time.Second)
	d.stop()

	time.Sleep(500 * time.Millisecond)
	runtime.Gosched()
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	finalized := runtime.NumGoroutine()
	t.Logf("=== AFTER STOP ===")
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)
	t.Logf("Goroutines after stop: %d", finalized)

	if cleanups != dispatched {
		t.Errorf("cleanup/init mismatch: dispatched=%d, cleanups=%d", dispatched, cleanups)
	}

	if finalized > 20 {
		t.Errorf("goroutine leak: %d goroutines still running", finalized)
	}
}

func TestStress_BurstLoadThenStop(t *testing.T) {
	numWorkers := 100
	d := newDispatcher("stress-burst-stop", numWorkers, newTestLogger("stress-burst-stop"))
	d.start()

	var dispatched int64
	var completed int64
	var cleanups int64
	var wg sync.WaitGroup

	for i := 0; i < 100000; i++ {
		job := &testJob{
			id: "job",
			ex: func(id string) error {
				atomic.AddInt64(&completed, 1)
				return nil
			},
			onFail: func(error) {},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.dispatch(job,
				func() { atomic.AddInt64(&dispatched, 1) },
				func() { atomic.AddInt64(&cleanups, 1) },
			)
		}()
	}

	wg.Wait()

	runtime.Gosched()
	goroutineDuring := runtime.NumGoroutine()
	t.Logf("=== DURING LOAD ===")
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)
	t.Logf("Goroutines: %d", goroutineDuring)

	time.Sleep(2 * time.Second)
	d.stop()

	time.Sleep(500 * time.Millisecond)
	runtime.Gosched()
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	finalized := runtime.NumGoroutine()
	t.Logf("=== AFTER STOP ===")
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)
	t.Logf("Goroutines after stop: %d", finalized)

	if cleanups != dispatched {
		t.Errorf("cleanup/init mismatch: dispatched=%d, cleanups=%d", dispatched, cleanups)
	}

	if finalized > 20 {
		t.Errorf("goroutine leak: %d goroutines still running", finalized)
	}
}

func TestStress_ConcurrentShutdownUnderLoad(t *testing.T) {
	numWorkers := 50
	d := newDispatcher("stress-shutdown-load", numWorkers, newTestLogger("stress-shutdown-load"))
	d.start()

	var dispatched int64
	var completed int64
	var cleanups int64
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for g := 0; g < 200; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					job := &testJob{
						id: "job",
						ex: func(id string) error {
							atomic.AddInt64(&completed, 1)
							time.Sleep(time.Microsecond * 50)
							return nil
						},
						onFail: func(error) {},
					}
					d.dispatch(job,
						func() { atomic.AddInt64(&dispatched, 1) },
						func() { atomic.AddInt64(&cleanups, 1) },
					)
				}
			}
		}()
	}

	time.Sleep(5 * time.Second)
	close(stopCh)
	wg.Wait()

	t.Logf("=== DURING SHUTDOWN ===")
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)

	time.Sleep(1 * time.Second)
	d.stop()

	time.Sleep(500 * time.Millisecond)
	runtime.Gosched()
	runtime.GC()

	finalized := runtime.NumGoroutine()
	t.Logf("=== AFTER STOP ===")
	t.Logf("dispatched: %d, completed: %d, cleanups: %d", dispatched, completed, cleanups)
	t.Logf("Goroutines after stop: %d", finalized)

	if cleanups != dispatched {
		t.Errorf("cleanup/init mismatch: dispatched=%d, cleanups=%d", dispatched, cleanups)
	}

	if finalized > 20 {
		t.Errorf("goroutine leak: %d goroutines still running", finalized)
	}
}

func TestStress_JobManagerHighLoad(t *testing.T) {
	numWorkers := 100
	jm := NewJobManager("stress-jm-highload", numWorkers, newTestLogger("stress-jm-highload"), nil)
	jm.Start()

	var submitted int64
	var completed int64
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					job := &testJob{
						id: "job",
						ex: func(id string) error {
							atomic.AddInt64(&completed, 1)
							time.Sleep(time.Microsecond * 100)
							return nil
						},
						onFail: func(error) {},
					}
					jm.AddJob(job, "queue-high")
					atomic.AddInt64(&submitted, 1)
				}
			}
		}()
	}

	time.Sleep(5 * time.Second)
	close(stopCh)
	wg.Wait()

	counts := jm.GetWorkerCounts()
	pendingJobs := jm.GetPendingJobCount()

	t.Logf("=== DURING LOAD ===")
	t.Logf("submitted: %d, completed: %d", submitted, completed)
	t.Logf("pending jobs: %d, worker counts: %v", pendingJobs, counts)

	time.Sleep(2 * time.Second)
	jm.Stop()

	time.Sleep(500 * time.Millisecond)
	runtime.Gosched()
	runtime.GC()

	finalized := runtime.NumGoroutine()
	t.Logf("=== AFTER STOP ===")
	t.Logf("submitted: %d, completed: %d", submitted, completed)
	t.Logf("Goroutines after stop: %d", finalized)

	for queueID, count := range counts {
		if count != 0 {
			t.Errorf("worker count leak: queue %s has count %d", queueID, count)
		}
	}

	if finalized > 20 {
		t.Errorf("goroutine leak: %d goroutines still running", finalized)
	}
}
