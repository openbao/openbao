// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"
)

func TestStringToFileModeFunc(t *testing.T) {
	hookFunc := StringToFileModeFunc()
	fileModeVal := reflect.ValueOf(os.FileMode(0))

	cases := []struct {
		name     string
		f, t     reflect.Value
		expected interface{}
		err      bool
	}{
		{"owner_only", reflect.ValueOf("0600"), fileModeVal, os.FileMode(0o600), false},
		{"high_bits", reflect.ValueOf("4600"), fileModeVal, os.FileMode(0o4600), false},

		// Prepends 0 automatically
		{"add_zero", reflect.ValueOf("600"), fileModeVal, os.FileMode(0o600), false},

		// Invalid file mode
		{"bad_mode", reflect.ValueOf("12345"), fileModeVal, "12345", true},

		// Invalid syntax
		{"bad_syntax", reflect.ValueOf("abcd"), fileModeVal, "abcd", true},

		// Different type
		{"two_strs", reflect.ValueOf("0600"), reflect.ValueOf(""), "0600", false},
		{"uint32", reflect.ValueOf("0600"), reflect.ValueOf(uint32(0)), "0600", false},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			actual, err := mapstructure.DecodeHookExec(hookFunc, tc.f, tc.t)
			if (err != nil) != tc.err {
				t.Fatalf("%s", err)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.expected, actual)
			}
		})
	}
}

func TestStringToWaitDurationHookFunc(t *testing.T) {
	f := StringToWaitDurationHookFunc()
	waitVal := reflect.ValueOf(WaitConfig{})

	cases := []struct {
		name     string
		f, t     reflect.Value
		expected interface{}
		err      bool
	}{
		{
			"min",
			reflect.ValueOf("5s"), waitVal,
			&WaitConfig{
				Min: TimeDuration(5 * time.Second),
				Max: TimeDuration(20 * time.Second),
			},
			false,
		},
		{
			"min_max",
			reflect.ValueOf("5s:10s"), waitVal,
			&WaitConfig{
				Min: TimeDuration(5 * time.Second),
				Max: TimeDuration(10 * time.Second),
			},
			false,
		},
		{
			"not_string",
			waitVal, waitVal,
			WaitConfig{},
			false,
		},
		{
			"not_wait",
			reflect.ValueOf("test"), reflect.ValueOf(""),
			"test",
			false,
		},
		{
			"bad_wait",
			reflect.ValueOf("nope"), waitVal,
			(*WaitConfig)(nil),
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			actual, err := mapstructure.DecodeHookExec(f, tc.f, tc.t)
			if (err != nil) != tc.err {
				t.Fatalf("%s", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.expected, actual)
			}
		})
	}
}

func TestConsulStringToStructFunc(t *testing.T) {
	f := ConsulStringToStructFunc()
	consulVal := reflect.ValueOf(ConsulConfig{})

	cases := []struct {
		name     string
		f, t     reflect.Value
		expected interface{}
		err      bool
	}{
		{
			"address",
			reflect.ValueOf("1.2.3.4"), consulVal,
			&ConsulConfig{
				Address: String("1.2.3.4"),
			},
			false,
		},
		{
			"not_string",
			consulVal, consulVal,
			ConsulConfig{},
			false,
		},
		{
			"not_consul",
			reflect.ValueOf("test"), reflect.ValueOf(""),
			"test",
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			actual, err := mapstructure.DecodeHookExec(f, tc.f, tc.t)
			if (err != nil) != tc.err {
				t.Fatalf("%s", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.expected, actual)
			}
		})
	}
}
