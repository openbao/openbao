// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"sort"
	"sync"
	"time"
)

// DefaultAnnounceInterval is how often a non-active node re-announces its full
// local spoke set to the active node. Aligned with clusterHeartbeatInterval so
// the relay's self-healing cadence matches the HA layer's.
const DefaultAnnounceInterval = 5 * time.Second

// announceInterval is the live re-announce cadence and the basis for the
// registry expiry window (3x). A package var, not the const, so HA tests can
// shrink it via TestingSetAnnounceInterval and not wait whole seconds.
var announceInterval = DefaultAnnounceInterval

// registryMissedAnnounces is how many announce intervals an entry may go
// unrefreshed before the active node considers the owning node gone and expires
// it. Three intervals tolerates a single dropped announce plus jitter without
// evicting a live spoke.
const registryMissedAnnounces = 3

// AnnouncedSpoke is one spoke as reported by the node that terminates its
// stream. It is the announcement's per-spoke payload, decoupled from the proto
// wire type so the registry stays pure logic (and unit-testable without gRPC).
type AnnouncedSpoke struct {
	SpokeName    string
	ConnectedAt  time.Time
	LastSeen     time.Time
	CertNotAfter time.Time
}

// SpokeLocation is a registry entry: where a spoke's stream lives, plus the
// liveness the owning node reported for it. Held only on the active node, only
// for spokes terminated by OTHER nodes (the active node finds its own spokes in
// the local map first). Derived state: never persisted, never replicated.
type SpokeLocation struct {
	SpokeName       string
	NodeClusterAddr string
	NodeID          string
	ConnectedAt     time.Time
	LastSeen        time.Time
	CertNotAfter    time.Time
	// lastAnnounce is when the active node last heard an announce carrying this
	// entry. Expiry is measured from here, not from LastSeen: a node can keep a
	// spoke healthy (fresh LastSeen) yet stop announcing (node partition), and
	// that node-level silence is what must expire the entry.
	lastAnnounce time.Time
}

// spokeRegistry is the active node's map of spoke_name -> owning node, built
// entirely from peer announcements (DESIGN.md "The spoke registry is built by
// announcement, not by gossip or lookup"). Safe for concurrent use.
type spokeRegistry struct {
	mu     sync.Mutex
	spokes map[string]*SpokeLocation
	ttl    time.Duration
	// now is injectable so tests can drive expiry deterministically.
	now func() time.Time
}

func newSpokeRegistry(announceInterval time.Duration) *spokeRegistry {
	if announceInterval <= 0 {
		announceInterval = DefaultAnnounceInterval
	}
	return &spokeRegistry{
		spokes: make(map[string]*SpokeLocation),
		ttl:    time.Duration(registryMissedAnnounces) * announceInterval,
		now:    time.Now,
	}
}

// applyFullAnnounce replaces the announcer's contribution to the registry with
// the full set it just reported. Every announce carries the announcer's
// complete local spoke set (not a delta), so this is idempotent: entries the
// announcer still holds are refreshed, and entries the announcer previously held
// but no longer lists are dropped.
//
// When an incoming spoke is already owned by a DIFFERENT node, ownership moves
// only if the announcer's stream is at least as fresh as the recorded one
// (ConnectedAt is not older). A spoke's stream is a single live connection, so
// the node it connected to most recently is the real owner: this lets a genuine
// migration from X to Y take over (Y's ConnectedAt is later), while rejecting a
// late, stale full announce from a former owner X that still lists a spoke it
// has since lost (X's ConnectedAt is older than Y's). Same-node announces always
// refresh. Any residual staleness is still self-corrected on the next full
// announce and, at routing time, by the one-shot re-resolve after "spoke not
// connected".
func (r *spokeRegistry) applyFullAnnounce(nodeClusterAddr, nodeID string, spokes []AnnouncedSpoke) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	incoming := make(map[string]struct{}, len(spokes))
	for _, s := range spokes {
		if s.SpokeName == "" {
			continue
		}
		incoming[s.SpokeName] = struct{}{}
		// Do not let an older stream from a different node reclaim a spoke that
		// has since migrated elsewhere. Same-node refreshes and equal/newer
		// streams win.
		if cur, ok := r.spokes[s.SpokeName]; ok &&
			cur.NodeClusterAddr != nodeClusterAddr &&
			s.ConnectedAt.Before(cur.ConnectedAt) {
			continue
		}
		r.spokes[s.SpokeName] = &SpokeLocation{
			SpokeName:       s.SpokeName,
			NodeClusterAddr: nodeClusterAddr,
			NodeID:          nodeID,
			ConnectedAt:     s.ConnectedAt,
			LastSeen:        s.LastSeen,
			CertNotAfter:    s.CertNotAfter,
			lastAnnounce:    now,
		}
	}

	// Drop entries this announcer used to own but no longer lists.
	for name, loc := range r.spokes {
		if loc.NodeClusterAddr != nodeClusterAddr {
			continue
		}
		if _, still := incoming[name]; !still {
			delete(r.spokes, name)
		}
	}
}

// resolve returns the owning-node location for a spoke, or (nil, false) if the
// spoke is unknown or its entry has expired (the owning node stopped
// announcing).
func (r *spokeRegistry) resolve(spokeName string) (SpokeLocation, bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	loc, ok := r.spokes[spokeName]
	if !ok {
		return SpokeLocation{}, false
	}
	if now.Sub(loc.lastAnnounce) > r.ttl {
		delete(r.spokes, spokeName)
		return SpokeLocation{}, false
	}
	return *loc, true
}

// forget removes a spoke from the registry. Used after a forward gets a
// definitive "spoke not connected" from the recorded owner, so the next resolve
// does not keep pointing at a node that no longer holds the stream.
func (r *spokeRegistry) forget(spokeName string) {
	r.mu.Lock()
	delete(r.spokes, spokeName)
	r.mu.Unlock()
}

// forgetIf removes a spoke entry only if it still names nodeClusterAddr. The
// one-shot re-resolve uses this so it drops the stale owner it just failed
// against without clobbering a fresh entry a concurrent announce may have
// written for the spoke's new owner.
func (r *spokeRegistry) forgetIf(spokeName, nodeClusterAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if loc, ok := r.spokes[spokeName]; ok && loc.NodeClusterAddr == nodeClusterAddr {
		delete(r.spokes, spokeName)
	}
}

// snapshot returns all non-expired entries, sorted by spoke name. Used by the
// cluster-wide observability path (relay/spokes, bao relay list). Also sweeps
// expired entries so the map does not grow without bound.
func (r *spokeRegistry) snapshot() []SpokeLocation {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SpokeLocation, 0, len(r.spokes))
	for name, loc := range r.spokes {
		if now.Sub(loc.lastAnnounce) > r.ttl {
			delete(r.spokes, name)
			continue
		}
		out = append(out, *loc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SpokeName < out[j].SpokeName })
	return out
}
