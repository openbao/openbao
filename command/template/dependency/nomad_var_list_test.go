// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"
	"time"

	nomadapi "github.com/hashicorp/nomad/api"
	"github.com/stretchr/testify/assert"
)

func TestNewNVListQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *NVListQuery
		err  bool
	}{
		{
			"empty",
			"",
			&NVListQuery{},
			false,
		},
		{
			"prefix",
			"prefix",
			&NVListQuery{
				prefix: "prefix",
			},
			false,
		},
		{
			"dots",
			"prefix.with.dots",
			&NVListQuery{
				prefix: "prefix.with.dots",
			},
			false,
		},
		{
			"slashes",
			"prefix/with/slashes",
			&NVListQuery{
				prefix: "prefix/with/slashes",
			},
			false,
		},
		{
			"dashes",
			"prefix-with-dashes",
			&NVListQuery{
				prefix: "prefix-with-dashes",
			},
			false,
		},
		{
			"leading_slash",
			"/leading/slash",
			&NVListQuery{
				prefix: "leading/slash",
			},
			false,
		},
		{
			"trailing_slash",
			"trailing/slash/",
			&NVListQuery{
				prefix: "trailing/slash/",
			},
			false,
		},
		{
			"underscores",
			"prefix_with_underscores",
			&NVListQuery{
				prefix: "prefix_with_underscores",
			},
			false,
		},
		{
			"special_characters",
			"config/facet:größe-lf-si",
			&NVListQuery{
				prefix: "config/facet:größe-lf-si",
			},
			false,
		},
		{
			"splat",
			"config/*/timeouts/",
			&NVListQuery{
				prefix: "config/*/timeouts/",
			},
			false,
		},
		{
			"slash",
			"/",
			&NVListQuery{
				prefix: "",
			},
			false,
		},
		{
			"slash-slash",
			"//",
			&NVListQuery{
				prefix: "",
			},
			false,
		},
		{
			"path-NS",
			"a/b@test",
			&NVListQuery{
				prefix:    "a/b",
				namespace: "test",
			},
			false,
		},
		{
			"path-splatNS",
			"a/b@*",
			&NVListQuery{
				prefix:    "a/b",
				namespace: "*",
			},
			false,
		},
		{
			"path-NS-region",
			"a/b@test.dc2",
			&NVListQuery{
				prefix:    "a/b",
				namespace: "test",
				region:    "dc2",
			},
			false,
		},
		{
			"path-splatNS-region",
			"a/b@*.dc2",
			&NVListQuery{
				prefix:    "a/b",
				namespace: "*",
				region:    "dc2",
			},
			false,
		},
		{
			"path-bad_splatNS-region",
			"a/b@bad*.dc2",
			nil,
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewNVListQuery("", tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestNVListQuery_Fetch(t *testing.T) {
	type nvmap map[string]string
	_ = testNomad.CreateVariable("test-kv-list/prefix/foo", nvmap{"bar": "barp"}, nil)
	_ = testNomad.CreateVariable("test-kv-list/prefix/zip", nvmap{"zap": "zapp"}, nil)
	_ = testNomad.CreateVariable("test-kv-list/prefix/wave/ocean", nvmap{"sleek": "sleekp"}, nil)

	nsOpt := &nomadapi.WriteOptions{Namespace: "test"}
	_ = testNomad.CreateVariable("test-kv-list/prefix/foo", nvmap{"bar": "barp"}, nsOpt)
	_ = testNomad.CreateVariable("test-kv-list/prefix/zip", nvmap{"zap": "zapp"}, nsOpt)
	_ = testNomad.CreateVariable("test-kv-list/prefix/wave/ocean", nvmap{"sleek": "sleekp"}, nsOpt)

	cases := []struct {
		name string
		i    string
		exp  []*NomadVarMeta
	}{
		{
			"exists",
			"test-kv-list/prefix",
			[]*NomadVarMeta{
				{Namespace: "default", Path: "test-kv-list/prefix/foo"},
				{Namespace: "default", Path: "test-kv-list/prefix/wave/ocean"},
				{Namespace: "default", Path: "test-kv-list/prefix/zip"},
			},
		},
		{
			"trailing",
			"test-kv-list/prefix/",
			[]*NomadVarMeta{
				{Namespace: "default", Path: "test-kv-list/prefix/foo"},
				{Namespace: "default", Path: "test-kv-list/prefix/wave/ocean"},
				{Namespace: "default", Path: "test-kv-list/prefix/zip"},
			},
		},
		{
			"no_exist",
			"test-kv-list/not/a/real/prefix/like/ever",
			[]*NomadVarMeta{},
		},
		{
			"exists_ns",
			"test-kv-list/prefix@test",
			[]*NomadVarMeta{
				{Namespace: "test", Path: "test-kv-list/prefix/foo"},
				{Namespace: "test", Path: "test-kv-list/prefix/wave/ocean"},
				{Namespace: "test", Path: "test-kv-list/prefix/zip"},
			},
		},
		{
			"splat",
			"test-kv-list/prefix@*",
			[]*NomadVarMeta{
				{Namespace: "default", Path: "test-kv-list/prefix/foo"},
				{Namespace: "default", Path: "test-kv-list/prefix/wave/ocean"},
				{Namespace: "default", Path: "test-kv-list/prefix/zip"},
				{Namespace: "test", Path: "test-kv-list/prefix/foo"},
				{Namespace: "test", Path: "test-kv-list/prefix/wave/ocean"},
				{Namespace: "test", Path: "test-kv-list/prefix/zip"},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNVListQuery("", tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			for _, p := range act.([]*NomadVarMeta) {
				p.CreateIndex = 0
				p.CreateTime = 0
				p.ModifyIndex = 0
				p.ModifyTime = 0
			}

			assert.ElementsMatch(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewNVListQuery("", "test-kv-list/prefix")
		if err != nil {
			t.Fatal(err)
		}

		dataCh := make(chan interface{}, 1)
		errCh := make(chan error, 1)
		go func() {
			for {
				data, _, err := d.Fetch(testClients, nil)
				if err != nil {
					errCh <- err
					return
				}
				dataCh <- data
			}
		}()

		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-dataCh:
		}

		d.Stop()

		select {
		case err := <-errCh:
			if err != ErrStopped {
				t.Fatal(err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	t.Run("fires_changes", func(t *testing.T) {
		d, err := NewNVListQuery("", "test-kv-list/prefix/")
		if err != nil {
			t.Fatal(err)
		}

		_, qm, err := d.Fetch(testClients, nil)
		if err != nil {
			t.Fatal(err)
		}

		dataCh := make(chan interface{}, 1)
		errCh := make(chan error, 1)
		go func() {
			data, _, err := d.Fetch(testClients, &QueryOptions{WaitIndex: qm.LastIndex})
			if err != nil {
				errCh <- err
				return
			}
			dataCh <- data
		}()

		_ = testNomad.CreateVariable("test-kv-list/prefix/foo", nvmap{"new-bar": "new-barp"}, nil)

		select {
		case err := <-errCh:
			t.Fatal(err)
		case data := <-dataCh:
			nVars := data.([]*NomadVarMeta)
			if len(nVars) == 0 {
				t.Fatal("bad length")
			}

			// Zero out the dynamic elements
			act := nVars[0]
			act.CreateIndex = 0
			act.CreateTime = 0
			act.ModifyIndex = 0
			act.ModifyTime = 0

			exp := &NomadVarMeta{Namespace: "default", Path: "test-kv-list/prefix/foo"}
			assert.Equal(t, exp, act)
		}
	})
}

func TestNVListQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"prefix",
			"prefix",
			"nomad.var.list(prefix@default.global)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNVListQuery("", tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
