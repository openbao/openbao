// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

func (c *Sys) Leader() (*LeaderResponse, error) {
	return c.LeaderWithContext(context.Background())
}

func (c *Sys) LeaderWithContext(ctx context.Context) (*LeaderResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/leader")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result LeaderResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

type LeaderResponse struct {
	HAEnabled            bool      `json:"ha_enabled"`
	IsSelf               bool      `json:"is_self,omitempty"`
	ActiveTime           time.Time `json:"active_time,omitzero"`
	LeaderAddress        string    `json:"leader_address,omitempty"`
	LeaderClusterAddress string    `json:"leader_cluster_address,omitempty"`
	RaftCommittedIndex   uint64    `json:"raft_committed_index,omitempty"`
	RaftAppliedIndex     uint64    `json:"raft_applied_index,omitempty"`
}
