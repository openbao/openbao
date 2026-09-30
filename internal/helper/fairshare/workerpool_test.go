// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fairshare

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestFairshare_newDispatcher(t *testing.T) {
	testCases := []struct {
		name               string
		numWorkers         int
		expectedNumWorkers int
	}{
		{
			name:               "",
			numWorkers:         0,
			expectedNumWorkers: 1,
		},
		{
			name:               "",
			numWorkers:         10,
			expectedNumWorkers: 10,
		},
		{
			name:               "test-dispatcher",
			numWorkers:         10,
			expectedNumWorkers: 10,
		},
	}

	l := newTestLogger("workerpool-test")
	for tcNum, tc := range testCases {
		d := newDispatcher(tc.name, tc.numWorkers, l)

		if tc.name != "" && d.name != tc.name {
			t.Errorf("tc %d: expected name %s, got %s", tcNum, tc.name, d.name)
		}
		if d.jobCh == nil {
			t.Errorf("tc %d: work channel not set up properly", tcNum)
		}
	}
}

func TestFairshare_createDispatcher(t *testing.T) {
	testCases := []struct {
		name               string
		numWorkers         int
		expectedNumWorkers int
	}{
		{
			name:               "",
			numWorkers:         -1,
			expectedNumWorkers: 1,
		},
		{
			name:               "",
			numWorkers:         0,
			expectedNumWorkers: 1,
		},
		{
			name:               "",
			numWorkers:         10,
			expectedNumWorkers: 10,
		},
		{
			name:               "",
			numWorkers:         10,
			expectedNumWorkers: 10,
		},
		{
			name:               "test-dispatcher",
			numWorkers:         10,
			expectedNumWorkers: 10,
		},
	}

	l := newTestLogger("workerpool-test")
	for tcNum, tc := range testCases {
		d := newDispatcher(tc.name, tc.numWorkers, l)
		if d == nil {
			t.Fatalf("tc %d: expected non-nil object", tcNum)
		}

		if tc.name != "" && d.name != tc.name {
			t.Errorf("tc %d: expected name %s, got %s", tcNum, tc.name, d.name)
		}
		if len(d.name) == 0 {
			t.Errorf("tc %d: expected name to be set", tcNum)
		}
		if d.maxWorkers != tc.expectedNumWorkers {
			t.Errorf("tc %d: expected %d workers, got %d", tcNum, tc.expectedNumWorkers, d.maxWorkers)
		}
		if d.jobCh == nil {
			t.Errorf("tc %d: work channel not set up properly", tcNum)
		}
		if d.quit == nil {
			t.Errorf("tc %d: expected non-nil quit channel", tcNum)
		}
		if d.logger == nil {
			t.Errorf("tc %d: expected non-nil logger", tcNum)
		}
	}
}

func TestFairshare_startWorker(t *testing.T) {
	d := newDispatcher("", 1, newTestLogger("workerpool-test"))
	defer d.stop()

	var wg sync.WaitGroup
	ex := func(_ string) error {
		wg.Done()
		return nil
	}
	onFail := func(_ error) {}

	job := newTestJob(t, "test job", ex, onFail)

	doneCh := make(chan struct{})
	timeout := time.After(5 * time.Second)

	wg.Add(1)
	d.dispatch(&job, nil, nil)
	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}
}

func TestFairshare_start(t *testing.T) {
	numJobs := 10
	var wg sync.WaitGroup
	ex := func(_ string) error {
		wg.Done()
		return nil
	}
	onFail := func(_ error) {}

	wg.Add(numJobs)
	d := newDispatcher("", 3, newTestLogger("workerpool-test"))
	defer d.stop()

	doneCh := make(chan struct{})
	timeout := time.After(5 * time.Second)
	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	for i := range numJobs {
		job := newTestJob(t, fmt.Sprintf("job-%d", i), ex, onFail)
		d.dispatch(&job, nil, nil)
	}

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}
}

func TestFairshare_stop(t *testing.T) {
	d := newDispatcher("", 5, newTestLogger("workerpool-test"))

	doneCh := make(chan struct{})
	timeout := time.After(5 * time.Second)

	go func() {
		d.stop()
		doneCh <- struct{}{}
	}()

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}
}

func TestFairshare_stopMultiple(t *testing.T) {
	d := newDispatcher("", 5, newTestLogger("workerpool-test"))

	doneCh := make(chan struct{})
	timeout := time.After(5 * time.Second)

	go func() {
		d.stop()
		doneCh <- struct{}{}
	}()

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}

	// essentially, we don't want to panic here
	var r any
	go func() {
		t.Helper()

		defer func() {
			r = recover()
			doneCh <- struct{}{}
		}()

		d.stop()
	}()

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}

	if r != nil {
		t.Fatalf("panic during second stop: %v", r)
	}
}

func TestFairshare_dispatch(t *testing.T) {
	d := newDispatcher("", 1, newTestLogger("workerpool-test"))
	defer d.stop()

	var wg sync.WaitGroup
	accumulatedIDs := make([]string, 0)
	ex := func(id string) error {
		accumulatedIDs = append(accumulatedIDs, id)
		wg.Done()
		return nil
	}
	onFail := func(_ error) {}

	expectedIDs := []string{"job-1", "job-2", "job-3", "job-4"}
	wg.Add(len(expectedIDs))

	go func() {
		for _, id := range expectedIDs {
			job := newTestJob(t, id, ex, onFail)
			d.dispatch(&job, nil, nil)
		}
	}()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	timeout := time.After(5 * time.Second)
	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}

	if !reflect.DeepEqual(accumulatedIDs, expectedIDs) {
		t.Fatalf("bad job ids. expected %v, got %v", expectedIDs, accumulatedIDs)
	}
}

func TestFairshare_jobFailure(t *testing.T) {
	numJobs := 10
	testErr := errors.New("test error")
	var wg sync.WaitGroup

	ex := func(_ string) error {
		return testErr
	}
	onFail := func(err error) {
		if err != testErr {
			t.Errorf("got unexpected error. expected %v, got %v", testErr, err)
		}

		wg.Done()
	}

	wg.Add(numJobs)
	d := newDispatcher("", 3, newTestLogger("workerpool-test"))
	defer d.stop()

	doneCh := make(chan struct{})
	timeout := time.After(5 * time.Second)
	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	for i := range numJobs {
		job := newTestJob(t, fmt.Sprintf("job-%d", i), ex, onFail)
		d.dispatch(&job, nil, nil)
	}

	select {
	case <-doneCh:
		break
	case <-timeout:
		t.Fatal("timed out")
	}
}

func TestFairshare_nilLoggerDispatcher(t *testing.T) {
	d := newDispatcher("test-job-mgr", 1, nil)
	if d.logger == nil {
		t.Error("logger not set up properly")
	}
}
