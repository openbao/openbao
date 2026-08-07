// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"context"
	"time"
)

// This file exposes a small, clearly-scoped surface for HA integration tests
// that live in another package (vault/external_tests/relay). It lets a test
// stand in for a real `bao relay run` spoke connection and drive a credential
// operation the way PluginProxy would, so the cross-node forwarding path can be
// exercised against a real in-process raft cluster without a live spoke or a
// real database. Nothing here is used by production code paths.

// TestingSetAnnounceInterval shrinks the announce cadence (and the derived
// registry expiry window) so HA tests do not wait whole seconds for a spoke to
// propagate to the active node. Call it before wiring nodes with SetRelayNode.
// Returns the previous value so a test can restore it.
func TestingSetAnnounceInterval(d time.Duration) time.Duration {
	prev := announceInterval
	announceInterval = d
	return prev
}

// TestingAttachSpoke injects a fake spoke stream into the proxy server bound to
// the given raft node id, answering each forwarded command via respond. It
// stands in for a real spoke Connect stream terminating on that node. The
// returned func detaches the spoke (as a disconnect would).
func TestingAttachSpoke(nodeID, spokeName string, respond func(command string) (output, errMsg string)) (detach func()) {
	ps := proxyServerForKey(nodeID)
	conn := newSpokeConnection(nil)
	conn.setCertNotAfter(time.Now().Add(90 * 24 * time.Hour))

	ps.mu.Lock()
	ps.spokes[spokeName] = conn
	ps.mu.Unlock()

	go func() {
		for {
			select {
			case <-conn.done:
				return
			case msg := <-conn.sendCh:
				if msg == nil || msg.RequestId == "" {
					continue // initial ack / heartbeat frames carry no request id
				}
				out, e := respond(msg.Command)
				conn.deliver(msg.RequestId, pendingResponse{output: out, err: e})
			}
		}
	}()

	// Announce immediately so the active node's registry learns the spoke
	// without waiting a full tick (best-effort; the periodic announce covers it
	// if the node is not yet wired).
	go ps.announceOnce()

	return func() {
		ps.mu.Lock()
		if cur, ok := ps.spokes[spokeName]; ok && cur == conn {
			delete(ps.spokes, spokeName)
		}
		ps.mu.Unlock()
		select {
		case <-conn.done:
		default:
			close(conn.done)
		}
		go ps.announceOnce()
	}
}

// TestingActiveRunCommand routes a command through the active node's proxy
// server, exactly as PluginProxy does on the active node. It returns the spoke's
// output (or an error), forwarding across the cluster port when the spoke's
// stream terminates on another node.
func TestingActiveRunCommand(ctx context.Context, spokeName, command string) (string, error) {
	return activeProxyServer().RunCommand(ctx, spokeName, command)
}

// TestingLocalSpokeCount returns how many spoke streams terminate locally on the
// proxy server bound to the given node id. Used to assert a stream survives a
// leadership change untouched.
func TestingLocalSpokeCount(nodeID string) int {
	ps := proxyServerForKey(nodeID)
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.spokes)
}
