// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !openbsd || !arm

package diagnose

import (
	"context"
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"
)

func diskUsage(ctx context.Context) error {
	// Disk usage
	partitions, err := disk.Partitions(false)
	if err != nil {
		return err
	}

	partitionExcludes := []string{"/boot"}
partLoop:
	for _, partition := range partitions {
		for _, exc := range partitionExcludes {
			if strings.HasPrefix(partition.Mountpoint, exc) {
				continue partLoop
			}
		}
		usage, err := disk.Usage(partition.Mountpoint)
		testName := "Check Disk Usage"
		if err != nil {
			Warn(ctx, fmt.Sprintf("Could not obtain partition usage for %s: %v.", partition.Mountpoint, err))
		} else {
			if usage.UsedPercent > 95 {
				SpotWarn(ctx, testName, fmt.Sprintf(partition.Mountpoint+" is %.2f percent full.", usage.UsedPercent),
					Advice("It is recommended to have more than five percent of the partition free."))
			} else if usage.Free < 1<<30 {
				quantity := usage.Free
				suffix := "bytes"
				switch {
				case quantity > 1024*1024*1024:
					quantity /= 1024 * 1024 * 1024
					suffix = "GB"
				case quantity > 1024*1024:
					quantity /= 1024 * 1024
					suffix = "MB"
				case quantity > 1024:
					quantity /= 1024
					suffix = "KB"
				}

				SpotWarn(ctx, testName, fmt.Sprintf(partition.Mountpoint+" has %d %s free.", quantity, suffix),
					Advice("It is recommended to have at least 1 GB of space free per partition."))
			} else {
				SpotOk(ctx, testName, partition.Mountpoint+" usage ok.")
			}
		}

	}
	return nil
}
