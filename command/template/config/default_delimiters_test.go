// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestDefaultDelims_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *DefaultDelims
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&DefaultDelims{},
		},
		{
			"copy",
			&DefaultDelims{
				Left:  String("<<"),
				Right: String(">>"),
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

func TestDefaultDelims_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *DefaultDelims
		b    *DefaultDelims
		r    *DefaultDelims
	}{
		{
			"nil_a",
			nil,
			&DefaultDelims{},
			&DefaultDelims{},
		},
		{
			"nil_b",
			&DefaultDelims{},
			nil,
			&DefaultDelims{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&DefaultDelims{},
			&DefaultDelims{},
			&DefaultDelims{},
		},
		{
			"left_delim_l",
			&DefaultDelims{Left: String("<<")},
			&DefaultDelims{},
			&DefaultDelims{Left: String("<<")},
		},
		{
			"left_delim_r",
			&DefaultDelims{},
			&DefaultDelims{Left: String("<<")},
			&DefaultDelims{Left: String("<<")},
		},
		{
			"left_delim_r2",
			&DefaultDelims{Left: String(">>")},
			&DefaultDelims{Left: String("<<")},
			&DefaultDelims{Left: String("<<")},
		},
		{
			"right_delim_l",
			&DefaultDelims{Right: String(">>")},
			&DefaultDelims{},
			&DefaultDelims{Right: String(">>")},
		},
		{
			"right_delim_r",
			&DefaultDelims{},
			&DefaultDelims{Right: String(">>")},
			&DefaultDelims{Right: String(">>")},
		},
		{
			"right_delim_r2",
			&DefaultDelims{Right: String("<<")},
			&DefaultDelims{Right: String(">>")},
			&DefaultDelims{Right: String(">>")},
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
