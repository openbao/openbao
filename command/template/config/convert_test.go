// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/consul-template/signals"
)

func TestBool(t *testing.T) {
	cases := []struct {
		name string
		b    bool
	}{
		{
			"true",
			true,
		},
		{
			"false",
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			b := Bool(tc.b)
			if *b != tc.b {
				t.Errorf("\nexp: %t\nact: %t", tc.b, *b)
			}
		})
	}
}

func TestBoolVal(t *testing.T) {
	cases := []struct {
		name string
		b    *bool
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			Bool(true),
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := BoolVal(tc.b)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestBoolGoString(t *testing.T) {
	cases := []struct {
		name string
		b    *bool
		e    string
	}{
		{
			"nil",
			nil,
			"(*bool)(nil)",
		},
		{
			"present",
			Bool(true),
			"true",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := BoolGoString(tc.b)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}

func TestBoolPresent(t *testing.T) {
	cases := []struct {
		name string
		b    *bool
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			Bool(false),
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := BoolPresent(tc.b)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestFileMode(t *testing.T) {
	cases := []struct {
		name string
		m    os.FileMode
	}{
		{
			"true",
			os.FileMode(0o644),
		},
		{
			"false",
			os.FileMode(0o000),
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			m := FileMode(tc.m)
			if *m != tc.m {
				t.Errorf("\nexp: %q\nact: %q", tc.m, *m)
			}
		})
	}
}

func TestFileModeVal(t *testing.T) {
	cases := []struct {
		name string
		m    *os.FileMode
		e    os.FileMode
	}{
		{
			"nil",
			nil,
			os.FileMode(0),
		},
		{
			"present",
			FileMode(0o644),
			os.FileMode(0o644),
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := FileModeVal(tc.m)
			if tc.e != a {
				t.Errorf("\nexp: %q\nact: %q", tc.e, a)
			}
		})
	}
}

func TestFileModeGoString(t *testing.T) {
	cases := []struct {
		name string
		m    *os.FileMode
		e    string
	}{
		{
			"nil",
			nil,
			"(*os.FileMode)(nil)",
		},
		{
			"present",
			FileMode(0),
			`"----------"`,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := FileModeGoString(tc.m)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}

func TestFileModePresent(t *testing.T) {
	cases := []struct {
		name string
		b    *os.FileMode
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			FileMode(0644),
			true,
		},
		{
			"present_zero_value",
			FileMode(0),
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := FileModePresent(tc.b)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestInt(t *testing.T) {
	cases := []struct {
		name string
		i    int
	}{
		{
			"zero",
			0,
		},
		{
			"present",
			1,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := Int(tc.i)
			if tc.i != *a {
				t.Errorf("\nexp: %q\nact: %q", tc.i, *a)
			}
		})
	}
}

func TestIntVal(t *testing.T) {
	cases := []struct {
		name string
		i    *int
		e    int
	}{
		{
			"nil",
			nil,
			0,
		},
		{
			"present",
			Int(3),
			3,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := IntVal(tc.i)
			if tc.e != a {
				t.Errorf("\nexp: %q\nact: %q", tc.e, a)
			}
		})
	}
}

func TestIntGoString(t *testing.T) {
	cases := []struct {
		name string
		i    *int
		e    string
	}{
		{
			"nil",
			nil,
			"(*int)(nil)",
		},
		{
			"present",
			Int(123),
			"123",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := IntGoString(tc.i)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}

func TestIntPresent(t *testing.T) {
	cases := []struct {
		name string
		i    *int
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			Int(123),
			true,
		},
		{
			"present_zero_value",
			Int(0),
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := IntPresent(tc.i)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestSignal(t *testing.T) {
	cases := []struct {
		name string
		s    os.Signal
	}{
		{
			"input",
			syscall.SIGHUP,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := Signal(tc.s)
			if *s != tc.s {
				t.Errorf("\nexp: %s\nact: %s", tc.s, *s)
			}
		})
	}
}

func TestSignalVal(t *testing.T) {
	cases := []struct {
		name string
		s    *os.Signal
		e    os.Signal
	}{
		{
			"nil",
			nil,
			nil,
		},
		{
			"input",
			Signal(syscall.SIGHUP),
			syscall.SIGHUP,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := SignalVal(tc.s)
			if tc.e != a {
				t.Errorf("\nexp: %s\nact: %s", tc.e, a)
			}
		})
	}
}

func TestSignalGoString(t *testing.T) {
	cases := []struct {
		name string
		s    *os.Signal
		e    string
	}{
		{
			"nil",
			nil,
			"(*os.Signal)(nil)",
		},
		{
			"present",
			Signal(syscall.SIGHUP),
			`"hangup"`,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := SignalGoString(tc.s)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}

func TestSignalPresent(t *testing.T) {
	cases := []struct {
		name string
		s    *os.Signal
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			Signal(syscall.SIGHUP),
			true,
		},
		{
			"present_zero_value",
			Signal(signals.SIGNULL),
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := SignalPresent(tc.s)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{
			"input",
			"hello world",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := String(tc.s)
			if *s != tc.s {
				t.Errorf("\nexp: %s\nact: %s", tc.s, *s)
			}
		})
	}
}

func TestStringVal(t *testing.T) {
	cases := []struct {
		name string
		s    *string
		e    string
	}{
		{
			"nil",
			nil,
			"",
		},
		{
			"input",
			String("hello"),
			"hello",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := StringVal(tc.s)
			if tc.e != a {
				t.Errorf("\nexp: %s\nact: %s", tc.e, a)
			}
		})
	}
}

func TestStringGoString(t *testing.T) {
	cases := []struct {
		name string
		s    *string
		e    string
	}{
		{
			"nil",
			nil,
			"(*string)(nil)",
		},
		{
			"present",
			String("hello"),
			`"hello"`,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := StringGoString(tc.s)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}

func TestStringPresent(t *testing.T) {
	cases := []struct {
		name string
		b    *string
		e    bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"present",
			String("hello"),
			true,
		},
		{
			"present_zero_value",
			String(""),
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := StringPresent(tc.b)
			if tc.e != a {
				t.Errorf("\nexp: %t\nact: %t", tc.e, a)
			}
		})
	}
}

func TestTimeDuration(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
	}{
		{
			"input",
			10 * time.Second,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d := TimeDuration(tc.d)
			if *d != tc.d {
				t.Errorf("\nexp: %s\nact: %s", tc.d, *d)
			}
		})
	}
}

func TestTimeDurationVal(t *testing.T) {
	cases := []struct {
		name string
		d    *time.Duration
		e    time.Duration
	}{
		{
			"nil",
			nil,
			time.Duration(0),
		},
		{
			"present",
			TimeDuration(10 * time.Second),
			10 * time.Second,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := TimeDurationVal(tc.d)
			if tc.e != a {
				t.Errorf("\nexp: %s\nact: %s", tc.e, a)
			}
		})
	}
}

func TestTimeDurationGoString(t *testing.T) {
	cases := []struct {
		name string
		d    *time.Duration
		e    string
	}{
		{
			"nil",
			nil,
			"(*time.Duration)(nil)",
		},
		{
			"present",
			TimeDuration(10 * time.Second),
			"10s",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			s := TimeDurationGoString(tc.d)
			if tc.e != s {
				t.Errorf("\nexp: %q\nact: %q", tc.e, s)
			}
		})
	}
}
