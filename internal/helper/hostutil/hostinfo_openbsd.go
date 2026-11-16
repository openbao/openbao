// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build openbsd

package hostutil

import (
	"context"
	"errors"
	"time"
)

type HostInfo struct {
	Timestamp time.Time `json:"timestamp"`
	CPU       []any     `json:"cpu"`
	CPUTimes  []any     `json:"cpu_times"`
	Disk      []any     `json:"disk"`
	Host      any       `json:"host"`
	Memory    any       `json:"memory"`
}

func CollectHostInfo(ctx context.Context) (*HostInfo, error) {
	return nil, errors.New("host info not supported on this platform")
}

func CollectHostMemory(ctx context.Context) (*VirtualMemoryStat, error) {
	return nil, errors.New("host info not supported on this platform")
}
