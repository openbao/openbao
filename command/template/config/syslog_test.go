// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSyslogConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *SyslogConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&SyslogConfig{},
		},
		{
			"same_enabled",
			&SyslogConfig{
				Enabled:  Bool(true),
				Facility: String("facility"),
				Name:     String("name"),
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

func TestSyslogConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *SyslogConfig
		b    *SyslogConfig
		r    *SyslogConfig
	}{
		{
			"nil_a",
			nil,
			&SyslogConfig{},
			&SyslogConfig{},
		},
		{
			"nil_b",
			&SyslogConfig{},
			nil,
			&SyslogConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&SyslogConfig{},
			&SyslogConfig{},
			&SyslogConfig{},
		},
		{
			"enabled_overrides",
			&SyslogConfig{Enabled: Bool(true)},
			&SyslogConfig{Enabled: Bool(false)},
			&SyslogConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&SyslogConfig{Enabled: Bool(true)},
			&SyslogConfig{},
			&SyslogConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&SyslogConfig{},
			&SyslogConfig{Enabled: Bool(true)},
			&SyslogConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&SyslogConfig{Enabled: Bool(true)},
			&SyslogConfig{Enabled: Bool(true)},
			&SyslogConfig{Enabled: Bool(true)},
		},
		{
			"facility_overrides",
			&SyslogConfig{Facility: String("facility")},
			&SyslogConfig{Facility: String("")},
			&SyslogConfig{Facility: String("")},
		},
		{
			"facility_empty_one",
			&SyslogConfig{Facility: String("facility")},
			&SyslogConfig{},
			&SyslogConfig{Facility: String("facility")},
		},
		{
			"facility_empty_two",
			&SyslogConfig{},
			&SyslogConfig{Facility: String("facility")},
			&SyslogConfig{Facility: String("facility")},
		},
		{
			"facility_same",
			&SyslogConfig{Facility: String("facility")},
			&SyslogConfig{Facility: String("facility")},
			&SyslogConfig{Facility: String("facility")},
		},
		{
			"name_overrides",
			&SyslogConfig{Name: String("name")},
			&SyslogConfig{Name: String("")},
			&SyslogConfig{Name: String("")},
		},
		{
			"name_empty_one",
			&SyslogConfig{Name: String("name")},
			&SyslogConfig{},
			&SyslogConfig{Name: String("name")},
		},
		{
			"name_empty_two",
			&SyslogConfig{},
			&SyslogConfig{Name: String("name")},
			&SyslogConfig{Name: String("name")},
		},
		{
			"name_same",
			&SyslogConfig{Name: String("name")},
			&SyslogConfig{Name: String("name")},
			&SyslogConfig{Name: String("name")},
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

func TestSyslogConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *SyslogConfig
		r    *SyslogConfig
	}{
		{
			"empty",
			&SyslogConfig{},
			&SyslogConfig{
				Enabled:  Bool(false),
				Facility: String(DefaultSyslogFacility),
				Name:     String(DefaultSyslogName),
			},
		},
		{
			"with_facility",
			&SyslogConfig{
				Facility: String("facility"),
			},
			&SyslogConfig{
				Enabled:  Bool(true),
				Facility: String("facility"),
				Name:     String(DefaultSyslogName),
			},
		},
		{
			"with_name",
			&SyslogConfig{
				Name: String("name"),
			},
			&SyslogConfig{
				Enabled:  Bool(true),
				Facility: String(DefaultSyslogFacility),
				Name:     String("name"),
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
