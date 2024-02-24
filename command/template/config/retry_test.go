// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestRetryFunc(t *testing.T) {
	cases := []struct {
		name string
		c    *RetryConfig
		a    *int
		rc   *bool
		rs   *time.Duration
	}{
		{
			"default, attempt 0",
			&RetryConfig{},
			Int(0),
			Bool(true),
			TimeDuration(250 * time.Millisecond),
		},
		{
			"default, attempt 1",
			&RetryConfig{},
			Int(1),
			Bool(true),
			TimeDuration(500 * time.Millisecond),
		},
		{
			"default, attempt 2",
			&RetryConfig{},
			Int(2),
			Bool(true),
			TimeDuration(1 * time.Second),
		},
		{
			"default, attempt 3",
			&RetryConfig{},
			Int(3),
			Bool(true),
			TimeDuration(2 * time.Second),
		},
		{
			"default, attempt 8",
			&RetryConfig{},
			Int(8),
			Bool(true),
			TimeDuration(1 * time.Minute),
		},
		{
			"default, attempt 9",
			&RetryConfig{},
			Int(9),
			Bool(true),
			TimeDuration(1 * time.Minute),
		},
		{
			"default, attempt 12",
			&RetryConfig{},
			Int(12),
			Bool(false),
			TimeDuration(0 * time.Second),
		},
		{
			"default, attempt 13",
			&RetryConfig{},
			Int(13),
			Bool(false),
			TimeDuration(0 * time.Second),
		},
		{
			"unlimited attempts",
			&RetryConfig{
				Attempts: Int(0),
			},
			Int(10),
			Bool(true),
			TimeDuration(1 * time.Minute),
		},
		{
			"disabled",
			&RetryConfig{
				Enabled: Bool(false),
			},
			Int(1),
			Bool(false),
			TimeDuration(0 * time.Second),
		},
		{
			"custom backoff, attempt 0",
			&RetryConfig{
				Backoff: TimeDuration(1 * time.Second),
			},
			Int(0),
			Bool(true),
			TimeDuration(1 * time.Second),
		},
		{
			"custom backoff, attempt 3",
			&RetryConfig{
				Backoff: TimeDuration(1 * time.Second),
			},
			Int(3),
			Bool(true),
			TimeDuration(8 * time.Second),
		},
		{
			"max backoff, attempt 3",
			&RetryConfig{
				Backoff:    TimeDuration(1 * time.Second),
				MaxBackoff: TimeDuration(5 * time.Second),
			},
			Int(3),
			Bool(true),
			TimeDuration(5 * time.Second),
		},
		{
			"max backoff, unlimited attempt 10",
			&RetryConfig{
				Attempts:   Int(0),
				MaxBackoff: TimeDuration(5 * time.Second),
			},
			Int(10),
			Bool(true),
			TimeDuration(5 * time.Second),
		},
		{
			"max backoff, attempt 100",
			&RetryConfig{
				Attempts:   Int(0),
				Backoff:    TimeDuration(1 * time.Millisecond),
				MaxBackoff: TimeDuration(2 * time.Millisecond),
			},
			Int(100),
			Bool(true),
			TimeDuration(2 * time.Millisecond),
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			tc.c.Finalize()
			c, s := tc.c.RetryFunc()(*tc.a)
			if (*tc.rc) != c {
				t.Errorf("\nexp continue: %#v\nact: %#v", *tc.rc, c)
			}
			if (*tc.rs) != s {
				t.Errorf("\nexp sleep time: %#v\nact: %#v", *tc.rs, s)
			}
		})
	}
}

func TestRetryConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *RetryConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&RetryConfig{},
		},
		{
			"same_enabled",
			&RetryConfig{
				Attempts: Int(25),
				Backoff:  TimeDuration(20 * time.Second),
				Enabled:  Bool(true),
			},
		},
		{
			"max_backoff",
			&RetryConfig{
				Attempts:   Int(0),
				Backoff:    TimeDuration(20 * time.Second),
				MaxBackoff: TimeDuration(100 * time.Second),
				Enabled:    Bool(true),
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

func TestRetryConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *RetryConfig
		b    *RetryConfig
		r    *RetryConfig
	}{
		{
			"nil_a",
			nil,
			&RetryConfig{},
			&RetryConfig{},
		},
		{
			"nil_b",
			&RetryConfig{},
			nil,
			&RetryConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&RetryConfig{},
			&RetryConfig{},
			&RetryConfig{},
		},
		{
			"attempts_overrides",
			&RetryConfig{Attempts: Int(10)},
			&RetryConfig{Attempts: Int(20)},
			&RetryConfig{Attempts: Int(20)},
		},
		{
			"attempts_empty_one",
			&RetryConfig{Attempts: Int(10)},
			&RetryConfig{},
			&RetryConfig{Attempts: Int(10)},
		},
		{
			"attempts_empty_two",
			&RetryConfig{},
			&RetryConfig{Attempts: Int(10)},
			&RetryConfig{Attempts: Int(10)},
		},
		{
			"attempts_same",
			&RetryConfig{Attempts: Int(10)},
			&RetryConfig{Attempts: Int(10)},
			&RetryConfig{Attempts: Int(10)},
		},

		{
			"backoff_overrides",
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
			&RetryConfig{Backoff: TimeDuration(20 * time.Second)},
			&RetryConfig{Backoff: TimeDuration(20 * time.Second)},
		},
		{
			"backoff_empty_one",
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
			&RetryConfig{},
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
		},
		{
			"backoff_empty_two",
			&RetryConfig{},
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
		},
		{
			"backoff_same",
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
			&RetryConfig{Backoff: TimeDuration(10 * time.Second)},
		},

		{
			"maxbackoff_overrides",
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
			&RetryConfig{MaxBackoff: TimeDuration(20 * time.Second)},
			&RetryConfig{MaxBackoff: TimeDuration(20 * time.Second)},
		},
		{
			"maxbackoff_empty_one",
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
			&RetryConfig{},
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
		},
		{
			"maxbackoff_empty_two",
			&RetryConfig{},
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
		},
		{
			"maxbackoff_same",
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
			&RetryConfig{MaxBackoff: TimeDuration(10 * time.Second)},
		},

		{
			"enabled_overrides",
			&RetryConfig{Enabled: Bool(true)},
			&RetryConfig{Enabled: Bool(false)},
			&RetryConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&RetryConfig{Enabled: Bool(true)},
			&RetryConfig{},
			&RetryConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&RetryConfig{},
			&RetryConfig{Enabled: Bool(true)},
			&RetryConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&RetryConfig{Enabled: Bool(true)},
			&RetryConfig{Enabled: Bool(true)},
			&RetryConfig{Enabled: Bool(true)},
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

func TestRetryConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *RetryConfig
		r    *RetryConfig
	}{
		{
			"empty",
			&RetryConfig{},
			&RetryConfig{
				Attempts:   Int(DefaultRetryAttempts),
				Backoff:    TimeDuration(DefaultRetryBackoff),
				MaxBackoff: TimeDuration(DefaultRetryMaxBackoff),
				Enabled:    Bool(true),
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
