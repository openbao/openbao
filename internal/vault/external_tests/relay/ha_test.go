// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	remotedb "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
)

// TestRelayHA_ForwardingAcrossNodes is the faithful, in-process reproduction of
// the bug the HA design fixes (DESIGN.md "HA: standby nodes and spoke stream
// ownership"): a spoke's stream terminates on a STANDBY node, yet a credential
// operation issued on the ACTIVE node must succeed, because the active node
// forwards the request over the cluster port to the node that holds the stream.
//
// It runs a real 3-node raft cluster with real cluster listeners, so the
// RelayForwarding ALPN traffic (announcements standby->active, RunCommand
// active->owner) crosses the wire exactly as it would in production. Each Core
// gets its own proxy server (keyed by raft node id), which is what makes the
// bug reproducible in-process at all: with the pre-refactor process-global
// singleton, all three nodes shared one spoke map and the active node would find
// the spoke locally, hiding the routing entirely.
//
// The spoke itself is stood in for by a fake stream (TestingAttachSpoke): this
// test exercises the hub-side routing, not the spoke daemon or a real database.
func TestRelayHA_ForwardingAcrossNodes(t *testing.T) {
	// Shrink the announce cadence so the active node's registry learns the spoke
	// in well under a second. Restore afterwards.
	prev := remotedb.TestingSetAnnounceInterval(150 * time.Millisecond)
	t.Cleanup(func() { remotedb.TestingSetAnnounceInterval(prev) })

	conf := &vault.CoreConfig{}
	opts := &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    3,
	}
	teststorage.RaftBackendSetup(conf, opts)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	// Wire each node's proxy server to its Core: sets the HA view (leadership,
	// seal state, cluster identity) and starts the spoke announcer. In
	// production the relay backend does this from its InitializeFunc; the test
	// does it directly so it does not depend on the relay mount being present.
	for _, c := range cluster.Cores {
		remotedb.SetRelayNode(c.RelayNodeView())
	}

	active := testhelpers.DeriveActiveCore(t, cluster)
	standbys := testhelpers.DeriveStandbyCores(t, cluster)
	if len(standbys) == 0 {
		t.Fatal("expected at least one standby")
	}
	standby := standbys[0]

	// Park a spoke stream on a STANDBY node, as a load balancer would.
	const spoke = "spoke-1"
	marker := "u_on_" + standby.NodeID
	detach := remotedb.TestingAttachSpoke(standby.NodeID, spoke, func(command string) (string, string) {
		return `{"username":"` + marker + `"}`, ""
	})
	defer detach()

	// A credential op on the ACTIVE node must forward to the standby-held spoke
	// and succeed. Poll: the first announce reaches the active within an
	// announce interval or two.
	out := mustRunCommandWithin(t, spoke, `{"method":"NewUser"}`, 5*time.Second)
	if !strings.Contains(out, marker) {
		t.Fatalf("forwarded output %q did not come from the standby %q", out, standby.NodeID)
	}
	t.Logf("credential op on active %q forwarded to spoke on standby %q: %s", active.NodeID, standby.NodeID, out)

	// --- Failover: step the active down. -----------------------------------
	// The spoke stream must NOT drop (it terminates on the standby, which is
	// untouched), and credentials must still issue after at most one announce
	// interval, with no spoke reconnect.
	localBefore := remotedb.TestingLocalSpokeCount(standby.NodeID)
	if localBefore < 1 {
		t.Fatalf("spoke not local on standby before failover (%d)", localBefore)
	}

	if err := active.Client.Sys().StepDown(); err != nil {
		t.Fatalf("step down active: %v", err)
	}
	testhelpers.WaitForActiveNode(t, cluster)

	// (a) The spoke stream survived the leadership change untouched.
	if got := remotedb.TestingLocalSpokeCount(standby.NodeID); got < 1 {
		t.Fatalf("spoke stream on standby was dropped during failover (count=%d)", got)
	}

	// (b) Credentials still issue on the NEW active. If the standby that holds
	// the spoke was itself promoted, this resolves locally; otherwise the new
	// active forwards to it. Either way it must succeed.
	out2 := mustRunCommandWithin(t, spoke, `{"method":"NewUser"}`, 5*time.Second)
	if !strings.Contains(out2, marker) {
		t.Fatalf("post-failover output %q did not come from the surviving spoke stream", out2)
	}
	t.Logf("after failover, credential op still forwarded to the surviving spoke: %s", out2)
}

// mustRunCommandWithin polls TestingActiveRunCommand until it succeeds or the
// deadline passes, tolerating the brief windows where leadership is unsettled or
// the registry has not yet received the announce.
func mustRunCommandWithin(t *testing.T, spoke, command string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		out, err := remotedb.TestingActiveRunCommand(ctx, spoke, command)
		cancel()
		if err == nil {
			return out
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("credential op never succeeded within %s: last error: %v", within, lastErr)
	return ""
}
