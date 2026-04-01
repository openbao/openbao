package fairshare

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackpressure_RejectsWhenQueueFull(t *testing.T) {
	numWorkers := 10
	queueSize := 100

	d := newDispatcher("backpressure-test", numWorkers, queueSize, newTestLogger("backpressure-test"))
	d.start()

	var accepted int64
	var rejected int64

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stopCh:
				return
			default:
				job := &testJob{
					id: "job",
					ex: func(id string) error {
						time.Sleep(10 * time.Millisecond)
						return nil
					},
					onFail: func(error) {},
				}
				if d.dispatch(job, func() { atomic.AddInt64(&accepted, 1) }, func() {}) {
					atomic.AddInt64(&accepted, 1)
				} else {
					atomic.AddInt64(&rejected, 1)
				}
			}
		}
	}()

	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		stats := d.Stats()
		t.Logf("[%ds] accepted=%d rejected=%d queue_depth=%d max_depth=%d",
			i+1, atomic.LoadInt64(&accepted), atomic.LoadInt64(&rejected), stats.QueueDepth, stats.MaxQueueDepth)

		if stats.QueueDepth >= int64(queueSize) && atomic.LoadInt64(&rejected) > 0 {
			t.Logf("Backpressure kicked in at %d seconds - queue full, jobs rejected", i+1)
			break
		}
	}

	close(stopCh)
	wg.Wait()
	d.stop()

	stats := d.Stats()
	t.Logf("=== Final ===")
	t.Logf("Accepted: %d", atomic.LoadInt64(&accepted))
	t.Logf("Rejected: %d", atomic.LoadInt64(&rejected))
	t.Logf("Max queue depth: %d", stats.MaxQueueDepth)
	t.Logf("Queue size was: %d", queueSize)

	if atomic.LoadInt64(&rejected) == 0 {
		t.Errorf("Expected rejections but got none - queueSize=%d may be too large", queueSize)
	}
}
