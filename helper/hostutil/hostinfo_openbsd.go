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
	Timestamp time.Time     `json:"timestamp"`
	CPU       []interface{} `json:"cpu"`
	CPUTimes  []interface{} `json:"cpu_times"`
	Disk      []interface{} `json:"disk"`
	Host      interface{}   `json:"host"`
	Memory    interface{}   `json:"memory"`
}

func CollectHostInfo(ctx context.Context) (*HostInfo, error) {
	return nil, errors.New("host info not supported on this platform")
}

func CollectHostMemory(ctx context.Context) (*VirtualMemoryStat, error) {
	return nil, errors.New("host info not supported on this platform")
}
