package fairshare

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStress_5MinuteSustainedLoad(t *testing.T) {
	numWorkers := 100
	duration := 5 * time.Minute
	targetRate := 10000

	t.Logf("=== 5-Minute Sustained Load Test ===")
	t.Logf("Workers: %d, Duration: %v, Target Rate: %d RPS", numWorkers, duration, targetRate)

	d := newDispatcher("stress-5min", numWorkers, 10000, newTestLogger("stress-5min"))
	d.start()

	var submitted int64
	var completed int64
	var rejected int64
	var goroutineBaseline = runtime.NumGoroutine()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	interval := time.Second / time.Duration(targetRate)

	for p := 0; p < 10; p++ {
		wg.Add(1)
		go func(producerID int) {
			defer wg.Done()
			jobNum := int64(0)
			for {
				select {
				case <-stopCh:
					return
				default:
					job := &testJob{
						id: fmt.Sprintf("p%d-j%d", producerID, jobNum),
						ex: func(id string) error {
							atomic.AddInt64(&completed, 1)
							time.Sleep(time.Microsecond * 50)
							return nil
						},
						onFail: func(error) {},
					}

					if d.dispatch(job, func() {}, func() {}) {
						atomic.AddInt64(&submitted, 1)
					} else {
						atomic.AddInt64(&rejected, 1)
					}
					time.Sleep(interval)
				}
			}
		}(p)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for i := 0; i < 10; i++ {
			<-ticker.C
			stats := d.Stats()
			current := runtime.NumGoroutine()
			t.Logf("[%3dm] submitted=%d completed=%d rejected=%d queue_depth=%d max_depth=%d goroutines=%d workers=%d",
				i+1, atomic.LoadInt64(&submitted), atomic.LoadInt64(&completed), atomic.LoadInt64(&rejected),
				stats.QueueDepth, stats.MaxQueueDepth, current-goroutineBaseline, stats.Workers)
		}
	}()

	time.Sleep(duration)
	close(stopCh)
	wg.Wait()

	stats := d.Stats()
	t.Logf("=== Load Complete, Waiting for Drain ===")
	t.Logf("Queue depth: %d, Workers: %d", stats.QueueDepth, stats.Workers)

	time.Sleep(5 * time.Second)
	d.stop()

	time.Sleep(1 * time.Second)
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	final := runtime.NumGoroutine()

	t.Logf("=== Final Results ===")
	t.Logf("Submitted: %d", atomic.LoadInt64(&submitted))
	t.Logf("Completed: %d", atomic.LoadInt64(&completed))
	t.Logf("Rejected:  %d", atomic.LoadInt64(&rejected))
	t.Logf("Lost:      %d",
		atomic.LoadInt64(&submitted)-atomic.LoadInt64(&completed)-atomic.LoadInt64(&rejected))
	t.Logf("Final goroutines: %d (baseline: %d)", final, goroutineBaseline)
	t.Logf("Max queue depth:  %d", stats.MaxQueueDepth)

	if final > goroutineBaseline+5 {
		t.Errorf("goroutine leak: %d goroutines", final-goroutineBaseline)
	}
}
