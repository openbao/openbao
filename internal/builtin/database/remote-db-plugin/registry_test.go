// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"testing"
	"time"
)

// fakeClock lets the registry's expiry be driven deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestRegistry(clk *fakeClock) *spokeRegistry {
	r := newSpokeRegistry(5 * time.Second) // ttl = 15s
	r.now = clk.now
	return r
}

func TestRegistry_AddAndResolve(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(900, 0), LastSeen: time.Unix(999, 0), CertNotAfter: time.Unix(5000, 0)},
	})

	loc, ok := r.resolve("s1")
	if !ok {
		t.Fatal("s1 should resolve")
	}
	if loc.NodeClusterAddr != "https://node-b:8201" || loc.NodeID != "node-b" {
		t.Fatalf("unexpected owner: %+v", loc)
	}
	if !loc.CertNotAfter.Equal(time.Unix(5000, 0)) {
		t.Fatalf("cert_not_after not preserved: %v", loc.CertNotAfter)
	}
	if _, ok := r.resolve("unknown"); ok {
		t.Fatal("unknown spoke must not resolve")
	}
}

func TestRegistry_ExpireAfterMissedAnnounces(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})

	// Just inside the ttl (15s): still present.
	clk.advance(14 * time.Second)
	if _, ok := r.resolve("s1"); !ok {
		t.Fatal("s1 should still be present at t+14s")
	}

	// Past the ttl with no re-announce: expired.
	clk.advance(2 * time.Second) // now t+16s from last announce
	if _, ok := r.resolve("s1"); ok {
		t.Fatal("s1 should have expired after 3 missed announces")
	}
}

func TestRegistry_ReannounceKeepsAlive(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})
	// Re-announce every 5s keeps refreshing lastAnnounce; after 30s it is alive.
	for i := 0; i < 6; i++ {
		clk.advance(5 * time.Second)
		r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})
	}
	if _, ok := r.resolve("s1"); !ok {
		t.Fatal("s1 kept alive by periodic re-announce should still resolve")
	}
}

// A full re-announce is authoritative for the announcing node: a spoke it no
// longer lists is dropped, even though other nodes' spokes are untouched.
func TestRegistry_FullAnnounceDropsMissingSpoke(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{
		{SpokeName: "s1"}, {SpokeName: "s2"},
	})
	// node-c owns s3.
	r.applyFullAnnounce("https://node-c:8201", "node-c", []AnnouncedSpoke{{SpokeName: "s3"}})

	// node-b re-announces WITHOUT s2 (its stream dropped): s2 must vanish, s1
	// stays, and node-c's s3 is untouched.
	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})

	if _, ok := r.resolve("s2"); ok {
		t.Fatal("s2 should be dropped by node-b's full re-announce")
	}
	if _, ok := r.resolve("s1"); !ok {
		t.Fatal("s1 should survive node-b's re-announce")
	}
	if loc, ok := r.resolve("s3"); !ok || loc.NodeID != "node-c" {
		t.Fatal("node-c's s3 must be untouched by node-b's announce")
	}
}

// A spoke moving from one node to another is owned by whoever announced last.
func TestRegistry_SpokeMovesToNewOwner(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})
	// s1 reconnects onto node-c; node-c announces it.
	r.applyFullAnnounce("https://node-c:8201", "node-c", []AnnouncedSpoke{{SpokeName: "s1"}})

	loc, ok := r.resolve("s1")
	if !ok || loc.NodeClusterAddr != "https://node-c:8201" {
		t.Fatalf("s1 should now be owned by node-c, got %+v (ok=%v)", loc, ok)
	}
}

func TestRegistry_ForgetRemovesEntry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)
	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})
	r.forget("s1")
	if _, ok := r.resolve("s1"); ok {
		t.Fatal("s1 should be gone after forget")
	}
}

func TestRegistry_SnapshotSortsAndSweeps(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)
	r.applyFullAnnounce("https://node-c:8201", "node-c", []AnnouncedSpoke{{SpokeName: "s3"}})
	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})

	snap := r.snapshot()
	if len(snap) != 2 || snap[0].SpokeName != "s1" || snap[1].SpokeName != "s3" {
		t.Fatalf("snapshot not sorted by name: %+v", snap)
	}

	// Let both expire; snapshot must sweep them.
	clk.advance(20 * time.Second)
	if snap := r.snapshot(); len(snap) != 0 {
		t.Fatalf("snapshot should be empty after expiry, got %+v", snap)
	}
}

// TestRegistry_StaleReclaimRejected: after a spoke migrates X->Y, a late full
// announce from X (still listing the spoke with its OLD ConnectedAt) must not
// reclaim ownership from Y, whose stream is newer.
func TestRegistry_StaleReclaimRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(100, 0)},
	})
	// s1 reconnects onto node-c (a newer stream); node-c announces it.
	r.applyFullAnnounce("https://node-c:8201", "node-c", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(200, 0)},
	})
	// A late, stale full announce from node-b still lists s1 at its old time.
	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(100, 0)},
	})

	loc, ok := r.resolve("s1")
	if !ok || loc.NodeClusterAddr != "https://node-c:8201" {
		t.Fatalf("stale reclaim from node-b should be rejected; want node-c, got %+v (ok=%v)", loc, ok)
	}
}

// TestRegistry_MigrationNewerStreamWins: a genuine migration (the new owner's
// ConnectedAt is later) takes over even though a different node owned the spoke.
func TestRegistry_MigrationNewerStreamWins(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)

	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(100, 0)},
	})
	r.applyFullAnnounce("https://node-c:8201", "node-c", []AnnouncedSpoke{
		{SpokeName: "s1", ConnectedAt: time.Unix(200, 0)},
	})

	if loc, ok := r.resolve("s1"); !ok || loc.NodeClusterAddr != "https://node-c:8201" {
		t.Fatalf("newer stream on node-c should win, got %+v (ok=%v)", loc, ok)
	}
}

// TestRegistry_ForgetIf: the compare-and-delete removes the entry only when it
// still names the given owner, so the one-shot re-resolve cannot clobber a fresh
// entry a concurrent announce wrote for the spoke's new owner.
func TestRegistry_ForgetIf(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := newTestRegistry(clk)
	r.applyFullAnnounce("https://node-b:8201", "node-b", []AnnouncedSpoke{{SpokeName: "s1"}})

	// Non-matching owner: must not delete.
	r.forgetIf("s1", "https://node-c:8201")
	if _, ok := r.resolve("s1"); !ok {
		t.Fatal("forgetIf with a non-matching owner must not delete")
	}
	// Matching owner: deletes.
	r.forgetIf("s1", "https://node-b:8201")
	if _, ok := r.resolve("s1"); ok {
		t.Fatal("forgetIf with the matching owner must delete")
	}
}
