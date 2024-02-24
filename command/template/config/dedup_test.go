// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestDedupConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *DedupConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&DedupConfig{},
		},
		{
			"copy",
			&DedupConfig{
				Enabled:  Bool(true),
				MaxStale: TimeDuration(30 * time.Second),
				Prefix:   String("prefix"),
				TTL:      TimeDuration(10 * time.Second),
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.a.Copy()
			if !reflect.DeepEqual(tc.a, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.a, r)
			}
		})
	}
}

func TestDedupConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *DedupConfig
		b    *DedupConfig
		r    *DedupConfig
	}{
		{
			"nil_a",
			nil,
			&DedupConfig{},
			&DedupConfig{},
		},
		{
			"nil_b",
			&DedupConfig{},
			nil,
			&DedupConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&DedupConfig{},
			&DedupConfig{},
			&DedupConfig{},
		},
		{
			"enabled_overrides",
			&DedupConfig{Enabled: Bool(true)},
			&DedupConfig{Enabled: Bool(false)},
			&DedupConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&DedupConfig{Enabled: Bool(true)},
			&DedupConfig{},
			&DedupConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&DedupConfig{},
			&DedupConfig{Enabled: Bool(true)},
			&DedupConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&DedupConfig{Enabled: Bool(true)},
			&DedupConfig{Enabled: Bool(true)},
			&DedupConfig{Enabled: Bool(true)},
		},
		{
			"max_stale_overrides",
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
			&DedupConfig{MaxStale: TimeDuration(20 * time.Second)},
			&DedupConfig{MaxStale: TimeDuration(20 * time.Second)},
		},
		{
			"max_stale_empty_one",
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
			&DedupConfig{},
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
		},
		{
			"max_stale_empty_two",
			&DedupConfig{},
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
		},
		{
			"max_stale_same",
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
			&DedupConfig{MaxStale: TimeDuration(10 * time.Second)},
		},
		{
			"prefix_overrides",
			&DedupConfig{Prefix: String("prefix")},
			&DedupConfig{Prefix: String("")},
			&DedupConfig{Prefix: String("")},
		},
		{
			"prefix_empty_one",
			&DedupConfig{Prefix: String("prefix")},
			&DedupConfig{},
			&DedupConfig{Prefix: String("prefix")},
		},
		{
			"prefix_empty_two",
			&DedupConfig{},
			&DedupConfig{Prefix: String("prefix")},
			&DedupConfig{Prefix: String("prefix")},
		},
		{
			"prefix_same",
			&DedupConfig{Prefix: String("prefix")},
			&DedupConfig{Prefix: String("prefix")},
			&DedupConfig{Prefix: String("prefix")},
		},
		{
			"ttl_overrides",
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
			&DedupConfig{TTL: TimeDuration(0 * time.Second)},
			&DedupConfig{TTL: TimeDuration(0 * time.Second)},
		},
		{
			"ttl_empty_one",
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
			&DedupConfig{},
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
		},
		{
			"ttl_empty_two",
			&DedupConfig{},
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
		},
		{
			"ttl_same",
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
			&DedupConfig{TTL: TimeDuration(10 * time.Second)},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.a.Merge(tc.b)
			if !reflect.DeepEqual(tc.r, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, r)
			}
		})
	}
}

func TestDedupConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *DedupConfig
		r    *DedupConfig
	}{
		{
			"empty",
			&DedupConfig{},
			&DedupConfig{
				Enabled:            Bool(false),
				MaxStale:           TimeDuration(DefaultDedupMaxStale),
				Prefix:             String(DefaultDedupPrefix),
				TTL:                TimeDuration(DefaultDedupTTL),
				BlockQueryWaitTime: TimeDuration(DefaultDedupBlockQueryWaitTime),
			},
		},
		{
			"with_max_stale",
			&DedupConfig{
				MaxStale: TimeDuration(10 * time.Second),
			},
			&DedupConfig{
				Enabled:            Bool(true),
				MaxStale:           TimeDuration(10 * time.Second),
				Prefix:             String(DefaultDedupPrefix),
				TTL:                TimeDuration(DefaultDedupTTL),
				BlockQueryWaitTime: TimeDuration(DefaultDedupBlockQueryWaitTime),
			},
		},
		{
			"with_prefix",
			&DedupConfig{
				Prefix: String("prefix"),
			},
			&DedupConfig{
				Enabled:            Bool(true),
				MaxStale:           TimeDuration(DefaultDedupMaxStale),
				Prefix:             String("prefix"),
				TTL:                TimeDuration(DefaultDedupTTL),
				BlockQueryWaitTime: TimeDuration(DefaultDedupBlockQueryWaitTime),
			},
		},
		{
			"with_ttl",
			&DedupConfig{
				TTL: TimeDuration(10 * time.Second),
			},
			&DedupConfig{
				Enabled:            Bool(true),
				MaxStale:           TimeDuration(DefaultDedupMaxStale),
				Prefix:             String(DefaultDedupPrefix),
				TTL:                TimeDuration(10 * time.Second),
				BlockQueryWaitTime: TimeDuration(DefaultDedupBlockQueryWaitTime),
			},
		},
		{
			"with_block_query_wait",
			&DedupConfig{
				BlockQueryWaitTime: TimeDuration(60 * time.Second),
			},
			&DedupConfig{
				Enabled:            Bool(true),
				MaxStale:           TimeDuration(DefaultDedupMaxStale),
				Prefix:             String(DefaultDedupPrefix),
				TTL:                TimeDuration(DefaultDedupTTL),
				BlockQueryWaitTime: TimeDuration(60 * time.Second),
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			tc.i.Finalize()
			if !reflect.DeepEqual(tc.r, tc.i) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, tc.i)
			}
		})
	}
}
