// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package watch

import (
	"fmt"
	"testing"

	dep "github.com/hashicorp/consul-template/dependency"
)

func TestAdd_updatesMap(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	d := &TestDep{}
	if _, err := w.Add(d); err != nil {
		t.Fatal(err)
	}

	_, exists := w.depViewMap[d.String()]
	if !exists {
		t.Errorf("expected Add to append to map")
	}
}

func TestAdd_exists(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	d := &TestDep{}
	w.depViewMap[d.String()] = &View{}

	added, err := w.Add(d)
	if err != nil {
		t.Fatal(err)
	}

	if added != false {
		t.Errorf("expected Add to return false")
	}
}

func TestAdd_startsViewPoll(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	added, err := w.Add(&TestDep{})
	if err != nil {
		t.Fatal(err)
	}

	if added != true {
		t.Errorf("expected Add to return true")
	}

	select {
	case err := <-w.errCh:
		t.Fatal(err)
	case <-w.dataCh:
		// Got data, which means the poll was started
	}
}

func TestWatching_notExists(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	d := &TestDep{}
	if w.Watching(d) == true {
		t.Errorf("expected to not be watching")
	}
}

func TestWatching_exists(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	d := &TestDep{}
	if _, err := w.Add(d); err != nil {
		t.Fatal(err)
	}

	if w.Watching(d) == false {
		t.Errorf("expected to be watching")
	}
}

func TestRemove_exists(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	d := &TestDep{}
	if _, err := w.Add(d); err != nil {
		t.Fatal(err)
	}

	removed := w.Remove(d)
	if removed != true {
		t.Error("expected Remove to return true")
	}

	if _, ok := w.depViewMap[d.String()]; ok {
		t.Error("expected dependency to be removed")
	}
}

func TestRemove_doesNotExist(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	removed := w.Remove(&TestDep{})
	if removed != false {
		t.Fatal("expected Remove to return false")
	}
}

func TestSize_empty(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	if w.Size() != 0 {
		t.Errorf("expected %d to be %d", w.Size(), 0)
	}
}

func TestSize_returnsNumViews(t *testing.T) {
	w := NewWatcher(&NewWatcherInput{
		Clients: dep.NewClientSet(),
		Once:    true,
	})

	for i := 0; i < 10; i++ {
		d := &TestDep{name: fmt.Sprintf("%d", i)}
		if _, err := w.Add(d); err != nil {
			t.Fatal(err)
		}
	}

	if w.Size() != 10 {
		t.Errorf("expected %d to be %d", w.Size(), 10)
	}
}
