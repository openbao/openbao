// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/queue"
)

// some tests rely on the ordering of items from this method
func selfEnrollmentTestCases() (tc []*MFASelfEnrollment) {
	// create a slice of items with times offset by these seconds
	for _, m := range []time.Duration{
		5,
		183600,  // 51 hours
		15,      // 15 seconds
		45,      // 45 seconds
		900,     // 15 minutes
		360,     // 6 minutes
		7200,    // 2 hours
		183600,  // 51 hours
		7201,    // 2 hours, 1 second
		115200,  // 32 hours
		1209600, // 2 weeks
	} {
		n := time.Now()
		ft := n.Add(time.Second * m)
		uid, err := uuid.GenerateUUID()
		if err != nil {
			continue
		}
		tc = append(tc, &MFASelfEnrollment{
			EntityID:      uid,
			TOTPSecret:    uid,
			TimeOfStorage: ft,
			RequestID:     uid,
		})
	}
	return tc
}

func TestMFASelfEnrollmentQueue_PushPopByKey(t *testing.T) {
	pq := NewMFASelfEnrollmentQueue()

	if pq.Len() != 0 {
		t.Fatalf("expected new queue to have zero size, got (%d)", pq.Len())
	}

	tc := selfEnrollmentTestCases()
	tcl := len(tc)
	for _, i := range tc {
		if err := pq.Push(i); err != nil {
			t.Fatal(err)
		}
	}

	if pq.Len() != tcl {
		t.Fatalf("error adding items, expected (%d) items, got (%d)", tcl, pq.Len())
	}

	item, err := pq.PopByKey(tc[0].RequestID)
	if err != nil {
		t.Fatalf("error popping item: %s", err)
	}
	if tc[0].RequestID != item.RequestID || tc[0].EntityID != item.EntityID || tc[0].TOTPSecret != item.TOTPSecret || tc[0].TimeOfStorage != item.TimeOfStorage {
		t.Fatalf("expected tc[0] and popped item to match, got (%#v) and (%#v)", tc[0], item)
	}

	// push item with duplicate key
	dErr := pq.Push(tc[1])
	if dErr != queue.ErrDuplicateItem {
		t.Fatal(err)
	}
	// push item with no key
	tc[2].RequestID = ""
	kErr := pq.Push(tc[2])
	if kErr != nil && kErr.Error() != "error adding item: Item Key is required" {
		t.Fatal(kErr)
	}

	peeked, err := pq.PeekMFASelfEnrollByID(tc[3].RequestID)
	if err != nil {
		t.Fatalf("error peeking item: %s", err)
	}
	if peeked == nil {
		t.Fatal("expected peeked item to be returned, got nil")
	}
	if peeked.RequestID != tc[3].RequestID || peeked.EntityID != tc[3].EntityID || peeked.TOTPSecret != tc[3].TOTPSecret || peeked.TimeOfStorage != tc[3].TimeOfStorage {
		t.Fatalf("expected peeked item to match stored item, got (%#v) and (%#v)", peeked, tc[3])
	}

	// check nil,nil error for not found
	i, err := pq.PopByKey("empty")
	if err != nil && i != nil {
		t.Fatalf("expected nil error for PopByKey of non-existing key, got: %s", err)
	}
}

func TestMFASelfEnrollmentQueue_RemoveStaleEntries(t *testing.T) {
	pq := NewMFASelfEnrollmentQueue()

	tc := selfEnrollmentTestCases()
	for _, i := range tc {
		if err := pq.Push(i); err != nil {
			t.Fatal(err)
		}
	}

	cutoffTime := time.Now().Add(371 * time.Second)
	timeout := time.Now().Add(5 * time.Second)
	for time.Now().Before(timeout) {
		pq.RemoveExpiredMfaSelfEnrollment(defaultMFASelfEnrollmentTTL, cutoffTime)
	}

	if pq.Len() != 8 {
		t.Fatalf("failed to remove %d stale entries", pq.Len())
	}
}
