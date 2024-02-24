// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package child

import (
	"os/exec"
	"reflect"
	"testing"
)

func Test_CommandPrep(t *testing.T) {
	type cmd []string
	cases := []struct {
		n     string
		in    cmd
		out   cmd
		subsh bool
		err   error
	}{
		{n: "empty", in: cmd{}, out: cmd{}, err: exec.ErrNotFound},
		{n: "''", in: cmd{""}, out: cmd{}, err: exec.ErrNotFound},
		{n: "' '", in: cmd{" "}, out: cmd{}, err: exec.ErrNotFound},
		{n: "'f'", in: cmd{"foo"}, out: cmd{"foo"}, err: nil},
		{n: "'f b'", in: cmd{"foo bar"}, subsh: true, out: cmd{"sh", "-c", "foo bar"}, err: nil},
		{n: "'f','b'", in: cmd{"foo", "bar"}, out: cmd{"foo", "bar"}, err: nil},
		{n: "'f','b','z'", in: cmd{"foo", "bar", "zed"}, out: cmd{"foo", "bar", "zed"}, err: nil},
	}
	for _, tc := range cases {
		t.Run(tc.n, func(t *testing.T) {
			out, subsh, err := CommandPrep(tc.in)
			if !reflect.DeepEqual(cmd(out), tc.out) {
				t.Errorf("bad commandPrep command output;"+
					"wanted: %#v, got %#v", tc.out, out)
			}
			if err != tc.err {
				t.Errorf("bad prepCommand error. wanted: %v, got %v", tc.err, err)
			}
			if tc.subsh != subsh {
				t.Errorf("incorrectly marked as using subshell")
			}
		})
	}
}
