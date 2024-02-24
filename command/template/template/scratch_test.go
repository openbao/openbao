// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"fmt"
	"reflect"
	"testing"
)

func TestScratch_Key(t *testing.T) {
	cases := []struct {
		name string
		s    *Scratch
		k    string
		e    bool
	}{
		{
			"no_exist",
			&Scratch{},
			"",
			false,
		},
		{
			"exist",
			&Scratch{
				values: map[string]interface{}{
					"foo": nil,
				},
			},
			"foo",
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.s.Key(tc.k)
			if !reflect.DeepEqual(tc.e, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, r)
			}
		})
	}
}

func TestScratch_Get(t *testing.T) {
	cases := []struct {
		name string
		s    *Scratch
		k    string
		e    interface{}
	}{
		{
			"no_exist",
			&Scratch{},
			"",
			nil,
		},
		{
			"exist",
			&Scratch{
				values: map[string]interface{}{
					"foo": "bar",
				},
			},
			"foo",
			"bar",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.s.Get(tc.k)
			if !reflect.DeepEqual(tc.e, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, r)
			}
		})
	}
}

func TestScratch_Set(t *testing.T) {
	cases := []struct {
		name string
		f    func(*Scratch)
		e    *Scratch
	}{
		{
			"no_exist",
			func(s *Scratch) {
				s.Set("foo", "bar")
			},
			&Scratch{
				values: map[string]interface{}{
					"foo": "bar",
				},
			},
		},
		{
			"overwrites",
			func(s *Scratch) {
				s.Set("foo", "bar")
				s.Set("foo", "zip")
			},
			&Scratch{
				values: map[string]interface{}{
					"foo": "zip",
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			var s Scratch
			tc.f(&s)

			if !reflect.DeepEqual(tc.e.values, s.values) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e.values, s.values)
			}
		})
	}
}

func TestScratch_SetX(t *testing.T) {
	cases := []struct {
		name string
		f    func(*Scratch)
		e    *Scratch
	}{
		{
			"no_exist",
			func(s *Scratch) {
				s.SetX("foo", "bar")
			},
			&Scratch{
				values: map[string]interface{}{
					"foo": "bar",
				},
			},
		},
		{
			"overwrites",
			func(s *Scratch) {
				s.SetX("foo", "bar")
				s.SetX("foo", "zip")
			},
			&Scratch{
				values: map[string]interface{}{
					"foo": "bar",
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			var s Scratch
			tc.f(&s)

			if !reflect.DeepEqual(tc.e.values, s.values) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e.values, s.values)
			}
		})
	}
}

func TestScratch_MapSet(t *testing.T) {
	cases := []struct {
		name string
		f    func(*Scratch)
		e    *Scratch
	}{
		{
			"no_exist",
			func(s *Scratch) {
				s.MapSet("a", "foo", "bar")
				s.MapSet("b", "foo", "bar")
			},
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{
						"foo": "bar",
					},
					"b": map[string]interface{}{
						"foo": "bar",
					},
				},
			},
		},
		{
			"overwrites",
			func(s *Scratch) {
				s.MapSet("a", "foo", "bar")
				s.MapSet("a", "foo", "zip")
			},
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{
						"foo": "zip",
					},
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			var s Scratch
			tc.f(&s)

			if !reflect.DeepEqual(tc.e.values, s.values) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e.values, s.values)
			}
		})
	}
}

func TestScratch_MapSetX(t *testing.T) {
	cases := []struct {
		name string
		f    func(*Scratch)
		e    *Scratch
	}{
		{
			"no_exist",
			func(s *Scratch) {
				s.MapSetX("a", "foo", "bar")
				s.MapSetX("b", "foo", "bar")
			},
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{
						"foo": "bar",
					},
					"b": map[string]interface{}{
						"foo": "bar",
					},
				},
			},
		},
		{
			"overwrites",
			func(s *Scratch) {
				s.MapSetX("a", "foo", "bar")
				s.MapSetX("a", "foo", "zip")
			},
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{
						"foo": "bar",
					},
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			var s Scratch
			tc.f(&s)

			if !reflect.DeepEqual(tc.e.values, s.values) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e.values, s.values)
			}
		})
	}
}

func TestScratch_MapValues(t *testing.T) {
	cases := []struct {
		name string
		s    *Scratch
		e    []interface{}
		err  bool
	}{
		{
			"sorted",
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{
						"foo":   "bar",
						"zip":   "zap",
						"peach": "banana",
					},
				},
			},
			[]interface{}{"bar", "banana", "zap"},
			false,
		},
		{
			"empty",
			&Scratch{
				values: map[string]interface{}{
					"a": map[string]interface{}{},
				},
			},
			[]interface{}{},
			false,
		},
		{
			"not_map",
			&Scratch{
				values: map[string]interface{}{
					"a": true,
				},
			},
			nil,
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r, err := tc.s.MapValues("a")
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, r)
			}
		})
	}
}
