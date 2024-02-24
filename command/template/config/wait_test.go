// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestWaitConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *WaitConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&WaitConfig{},
		},
		{
			"same_enabled",
			&WaitConfig{
				Enabled: Bool(true),
				Min:     TimeDuration(10 * time.Second),
				Max:     TimeDuration(20 * time.Second),
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

func TestWaitConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *WaitConfig
		b    *WaitConfig
		r    *WaitConfig
	}{
		{
			"nil_a",
			nil,
			&WaitConfig{},
			&WaitConfig{},
		},
		{
			"nil_b",
			&WaitConfig{},
			nil,
			&WaitConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&WaitConfig{},
			&WaitConfig{},
			&WaitConfig{},
		},
		{
			"enabled_overrides",
			&WaitConfig{Enabled: Bool(true)},
			&WaitConfig{Enabled: Bool(false)},
			&WaitConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&WaitConfig{Enabled: Bool(true)},
			&WaitConfig{},
			&WaitConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&WaitConfig{},
			&WaitConfig{Enabled: Bool(true)},
			&WaitConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&WaitConfig{Enabled: Bool(true)},
			&WaitConfig{Enabled: Bool(true)},
			&WaitConfig{Enabled: Bool(true)},
		},
		{
			"min_overrides",
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
			&WaitConfig{Min: TimeDuration(0 * time.Second)},
			&WaitConfig{Min: TimeDuration(0 * time.Second)},
		},
		{
			"min_empty_one",
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
			&WaitConfig{},
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
		},
		{
			"min_empty_two",
			&WaitConfig{},
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
		},
		{
			"min_same",
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
			&WaitConfig{Min: TimeDuration(10 * time.Second)},
		},
		{
			"max_overrides",
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
			&WaitConfig{Max: TimeDuration(0 * time.Second)},
			&WaitConfig{Max: TimeDuration(0 * time.Second)},
		},
		{
			"max_empty_one",
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
			&WaitConfig{},
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
		},
		{
			"max_empty_two",
			&WaitConfig{},
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
		},
		{
			"max_same",
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
			&WaitConfig{Max: TimeDuration(20 * time.Second)},
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

func TestWaitConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *WaitConfig
		r    *WaitConfig
	}{
		{
			"empty",
			&WaitConfig{},
			&WaitConfig{
				Enabled: Bool(false),
				Max:     TimeDuration(0 * time.Second),
				Min:     TimeDuration(0 * time.Second),
			},
		},
		{
			"with_min",
			&WaitConfig{
				Min: TimeDuration(10 * time.Second),
			},
			&WaitConfig{
				Enabled: Bool(true),
				Max:     TimeDuration(40 * time.Second),
				Min:     TimeDuration(10 * time.Second),
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

func TestParseWaitConfig(t *testing.T) {
	cases := []struct {
		name string
		i    string
		r    *WaitConfig
		e    error
	}{
		{
			"empty",
			"",
			nil,
			ErrWaitStringEmpty,
		},
		{
			"empty_spaces",
			" ",
			nil,
			ErrWaitStringEmpty,
		},
		{
			"too_many_args",
			"5s:10s:15s",
			nil,
			ErrWaitInvalidFormat,
		},
		{
			"min",
			"5s",
			&WaitConfig{
				Min: TimeDuration(5 * time.Second),
				Max: TimeDuration(20 * time.Second),
			},
			nil,
		},
		{
			"min_max",
			"5s:10s",
			&WaitConfig{
				Min: TimeDuration(5 * time.Second),
				Max: TimeDuration(10 * time.Second),
			},
			nil,
		},
		{
			"min_negative",
			"-5s",
			nil,
			ErrWaitNegative,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			w, err := ParseWaitConfig(tc.i)
			if err != nil {
				if tc.e != nil {
					if err != tc.e {
						t.Errorf("\nexp: %#v\nact: %#v", tc.e, err)
					}
				} else {
					t.Fatal(err)
				}
			}

			if !reflect.DeepEqual(tc.r, w) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, w)
			}
		})
	}
}
