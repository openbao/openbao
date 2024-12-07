// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"context"
	"encoding/json"
	"maps"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
	"github.com/openbao/openbao/sdk/v2/physical"
)

// Ensure that the Delegate implements the ApplicationIntegration interface
var _ autopilot.ApplicationIntegration = (*Delegate)(nil)

// Delegate is an implementation of autopilot.ApplicationIntegration interface.
// This is used by the autopilot library to retrieve information and to have
// application specific tasks performed.
type Delegate struct {
	*RaftBackend

	// dl is a lock dedicated for guarding delegate's fields
	dl               sync.RWMutex
	inflightRemovals map[raft.ServerID]bool
	emptyVersionLogs map[raft.ServerID]struct{}
	// added in OpenBao 2.2 to support permanent non-voters
	permanentNonVoters map[raft.ServerID]bool
}

func NewDelegate(b *RaftBackend) *Delegate {
	return &Delegate{
		RaftBackend:        b,
		inflightRemovals:   make(map[raft.ServerID]bool),
		emptyVersionLogs:   make(map[raft.ServerID]struct{}),
		permanentNonVoters: make(map[raft.ServerID]bool),
	}
}

// AutopilotConfig is called by the autopilot library to know the desired
// autopilot configuration.
func (d *Delegate) AutopilotConfig() *autopilot.Config {
	// Always fetch non-voters before returning the config
	err := d.FetchNonVoters()
	if err != nil {
		d.logger.Error("failed to fetch non-voters", "error", err)
	}
	// Get read lock for autopilot config
	d.l.RLock()
	defer d.l.RUnlock()
	// Get read lock for delegate's fields
	d.dl.RLock()
	defer d.dl.RUnlock()
	config := &autopilot.Config{
		CleanupDeadServers:      d.autopilotConfig.CleanupDeadServers,
		LastContactThreshold:    d.autopilotConfig.LastContactThreshold,
		MaxTrailingLogs:         d.autopilotConfig.MaxTrailingLogs,
		MinQuorum:               d.autopilotConfig.MinQuorum,
		ServerStabilizationTime: d.autopilotConfig.ServerStabilizationTime,
		Ext:                     maps.Clone(d.permanentNonVoters),
	}
	return config
}

// NotifyState is called by the autopilot library whenever there is a state
// change. We update a few metrics when this happens.
func (d *Delegate) NotifyState(state *autopilot.State) {
	if d.raft.State() == raft.Leader {
		metrics.SetGauge([]string{"autopilot", "failure_tolerance"}, float32(state.FailureTolerance))
		if state.Healthy {
			metrics.SetGauge([]string{"autopilot", "healthy"}, 1)
		} else {
			metrics.SetGauge([]string{"autopilot", "healthy"}, 0)
		}

		for id, state := range state.Servers {
			labels := []metrics.Label{
				{
					Name:  "node_id",
					Value: string(id),
				},
			}
			if state.Health.Healthy {
				metrics.SetGaugeWithLabels([]string{"autopilot", "node", "healthy"}, 1, labels)
			} else {
				metrics.SetGaugeWithLabels([]string{"autopilot", "node", "healthy"}, 0, labels)
			}
		}
	}
}

// FetchServerStats is called by the autopilot library to retrieve information
// about all the nodes in the raft cluster.
func (d *Delegate) FetchServerStats(ctx context.Context, servers map[raft.ServerID]*autopilot.Server) map[raft.ServerID]*autopilot.ServerStats {
	ret := make(map[raft.ServerID]*autopilot.ServerStats)

	d.l.RLock()
	followerStates := d.followerStates
	d.l.RUnlock()

	followerStates.l.RLock()
	defer followerStates.l.RUnlock()

	now := time.Now()
	for id, followerState := range followerStates.followers {
		ret[raft.ServerID(id)] = &autopilot.ServerStats{
			LastContact: now.Sub(followerState.LastHeartbeat),
			LastTerm:    followerState.LastTerm,
			LastIndex:   followerState.AppliedIndex,
		}
	}

	leaderState, _ := d.fsm.LatestState()
	ret[raft.ServerID(d.localID)] = &autopilot.ServerStats{
		LastTerm:  leaderState.Term,
		LastIndex: leaderState.Index,
	}

	return ret
}

// KnownServers is called by the autopilot library to know the status of each
// node in the raft cluster. If the application thinks that certain nodes left,
// it is here that we let the autopilot library know of the same.
func (d *Delegate) KnownServers() map[raft.ServerID]*autopilot.Server {
	d.l.RLock()
	defer d.l.RUnlock()
	future := d.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		d.logger.Error("failed to get raft configuration when computing known servers", "error", err)
		return nil
	}

	apServerStates := d.autopilot.GetState().Servers
	servers := future.Configuration().Servers
	serverIDs := make([]string, 0, len(servers))
	for _, server := range servers {
		serverIDs = append(serverIDs, string(server.ID))
	}

	d.followerStates.l.RLock()
	defer d.followerStates.l.RUnlock()

	ret := make(map[raft.ServerID]*autopilot.Server)
	for id, state := range d.followerStates.followers {
		// If the server is not in raft configuration, even if we received a follower
		// heartbeat, it shouldn't be a known server for autopilot.
		if !strutil.StrListContains(serverIDs, id) {
			continue
		}

		// If version isn't found in the state, fake it using the version from the leader so that autopilot
		// doesn't demote the node to a non-voter, just because of a missed heartbeat.
		currentServerID := raft.ServerID(id)
		followerVersion := state.Version
		leaderVersion := d.effectiveSDKVersion
		d.dl.Lock()
		if followerVersion == "" {
			if _, ok := d.emptyVersionLogs[currentServerID]; !ok {
				d.logger.Trace("received empty Vault version in heartbeat state. faking it with the leader version for now", "id", id, "leader version", leaderVersion)
				d.emptyVersionLogs[currentServerID] = struct{}{}
			}
			followerVersion = leaderVersion
		} else {
			delete(d.emptyVersionLogs, currentServerID)
		}
		d.dl.Unlock()

		server := &autopilot.Server{
			ID:          currentServerID,
			Name:        id,
			RaftVersion: raft.ProtocolVersionMax,
			Meta:        nil,
			Version:     followerVersion,
			Ext:         nil,
		}

		// As KnownServers is a delegate called by autopilot let's check if we already
		// had this data in the correct format and use it. If we don't (which sounds a
		// bit sad, unless this ISN'T a voter) then as a fail-safe, let's try what we've
		// done elsewhere in code to check the desired suffrage and manually set NodeType
		// based on whether that's a voter or not. If we don't  do either of these
		// things, NodeType isn't set which means technically it's not a voter.
		// It shouldn't be a voter and end up in this state.
		if apServerState, found := apServerStates[raft.ServerID(id)]; found && apServerState.Server.NodeType != "" {
			server.NodeType = apServerState.Server.NodeType
		} else if d.IsNonVoter(raft.ServerID(id)) {
			server.NodeType = NodeNonVoter
		} else if state.DesiredSuffrage == "voter" {
			server.NodeType = autopilot.NodeVoter
		}

		switch state.IsDead.Load() {
		case true:
			d.logger.Debug("informing autopilot that the node left", "id", id)
			server.NodeStatus = autopilot.NodeLeft
		default:
			server.NodeStatus = autopilot.NodeAlive
		}

		ret[raft.ServerID(id)] = server
	}

	// Add the leader
	ret[raft.ServerID(d.localID)] = &autopilot.Server{
		ID:          raft.ServerID(d.localID),
		Name:        d.localID,
		RaftVersion: raft.ProtocolVersionMax,
		NodeStatus:  autopilot.NodeAlive,
		NodeType:    autopilot.NodeVoter, // The leader must be a voter
		Meta:        nil,
		Version:     d.effectiveSDKVersion,
		Ext:         nil,
		IsLeader:    true,
	}

	return ret
}

// RemoveFailedServer is called by the autopilot library when it desires a node
// to be removed from the raft configuration. This function removes the node
// from the raft cluster and stops tracking its information in follower states.
// This function needs to return quickly. Hence removal is performed in a
// goroutine.
func (d *Delegate) RemoveFailedServer(server *autopilot.Server) {
	go func() {
		added := false
		defer func() {
			if added {
				d.dl.Lock()
				delete(d.inflightRemovals, server.ID)
				d.dl.Unlock()
			}
		}()

		d.dl.Lock()
		_, ok := d.inflightRemovals[server.ID]
		if ok {
			d.logger.Info("removal of dead server is already initiated", "id", server.ID)
			d.dl.Unlock()
			return
		}

		added = true
		d.inflightRemovals[server.ID] = true
		d.dl.Unlock()

		d.logger.Info("removing dead server from raft configuration", "id", server.ID)
		if future := d.raft.RemoveServer(server.ID, 0, 0); future.Error() != nil {
			d.logger.Error("failed to remove server", "server_id", server.ID, "server_address", server.Address, "server_name", server.Name, "error", future.Error())
			return
		}

		// remove failed server from non-voters
		err := d.RemoveNonVoter(server.ID)
		if err != nil {
			d.logger.Error("failed to remove server from non-voters", "server_id", server.ID, "error", err)
		}
		d.followerStates.Delete(string(server.ID))
	}()
}

// AddNonVoter mark a node as permanent non-voter
func (d *Delegate) AddNonVoter(id raft.ServerID) error {
	d.dl.Lock()
	d.permanentNonVoters[id] = true
	d.dl.Unlock()

	return d.StoreNonVoters()
}

// IsNonVoter check if a node is a permanent non-voter
func (d *Delegate) IsNonVoter(id raft.ServerID) bool {
	d.dl.RLock()
	defer d.dl.RUnlock()
	if _, ok := d.permanentNonVoters[id]; ok {
		return ok
	}
	return false
}

// RemoveNonVoter remove a node from permanent non-voter list
func (d *Delegate) RemoveNonVoter(id raft.ServerID) error {
	d.dl.Lock()
	delete(d.permanentNonVoters, id)
	d.dl.Unlock()

	return d.StoreNonVoters()
}

// NonVoters returns the list of permanent non-voters
func (d *Delegate) NonVoters() []raft.ServerID {
	d.dl.RLock()
	defer d.dl.RUnlock()
	nonVoters := make([]raft.ServerID, 0, len(d.permanentNonVoters))
	for id := range d.permanentNonVoters {
		nonVoters = append(nonVoters, id)
	}
	return nonVoters
}

// StoreNonVoters stores the permanent non-voters in the physical store
func (d *Delegate) StoreNonVoters() error {
	d.dl.RLock()
	defer d.dl.RUnlock()
	d.logger.Trace("updating non-voters", "non_voters", d.permanentNonVoters)
	v, err := json.Marshal(d.permanentNonVoters)
	if err != nil {
		return err
	}
	e := physical.Entry{
		Key:   NonVoterPath,
		Value: v,
	}

	return d.Put(context.Background(), &e)
}

// FetchNonVoters fetches the permanent non-voters from the physical store
func (d *Delegate) FetchNonVoters() error {
	e, err := d.Get(context.Background(), NonVoterPath)
	if err != nil {
		d.logger.Error("failed to fetch non voters", "error", err)
		return err
	}

	if e == nil {
		d.logger.Trace("no non-voters")
		return nil
	}

	var nonVoters map[raft.ServerID]bool
	if err := json.Unmarshal(e.Value, &nonVoters); err != nil {
		d.logger.Error("failed to unmarshal non-voters", "error", err)
		return err
	}

	d.dl.RLock()
	nV := d.permanentNonVoters
	d.dl.RUnlock()
	if !maps.Equal(nV, nonVoters) {
		d.dl.Lock()
		d.permanentNonVoters = nonVoters
		d.dl.Unlock()
	}
	return nil
}
