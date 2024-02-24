// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"
	"time"

	nomadapi "github.com/hashicorp/nomad/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNVGetQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *NVGetQuery
		err  bool
	}{
		{
			"empty",
			"",
			&NVGetQuery{},
			false,
		},

		{
			"dc_only",
			"@dc1",
			nil,
			true,
		},
		{
			"path",
			"path",
			&NVGetQuery{
				path: "path",
			},
			false,
		},
		{
			"dots",
			"path.with.dots",
			&NVGetQuery{
				path: "path.with.dots",
			},
			false,
		},
		{
			"slashes",
			"path/with/slashes",
			&NVGetQuery{
				path: "path/with/slashes",
			},
			false,
		},
		{
			"dashes",
			"path-with-dashes",
			&NVGetQuery{
				path: "path-with-dashes",
			},
			false,
		},
		{
			"leading_slash",
			"/leading/slash",
			&NVGetQuery{
				path: "leading/slash",
			},
			false,
		},
		{
			"trailing_slash",
			"trailing/slash/",
			&NVGetQuery{
				path: "trailing/slash",
			},
			false,
		},
		{
			"underscores",
			"path_with_underscores",
			&NVGetQuery{
				path: "path_with_underscores",
			},
			false,
		},
		{
			"special_characters",
			"config/facet:größe-lf-si",
			&NVGetQuery{
				path: "config/facet:größe-lf-si",
			},
			false,
		},
		{
			"splat",
			"config/*/timeouts/",
			&NVGetQuery{
				path: "config/*/timeouts",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewNVGetQuery("", tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
	fmt.Println("done")
}

func TestNVGetQuery_Fetch(t *testing.T) {
	type nvmap map[string]string
	_ = testNomad.CreateVariable("test-kv-get/path", nvmap{"bar": "barp"}, nil)
	_ = testNomad.CreateNamespace("test", nil)
	_ = testNomad.CreateVariable("test-ns-get/path", nvmap{"car": "carp"}, &nomadapi.WriteOptions{Namespace: "test"})
	cases := []struct {
		name string
		i    string
		exp  interface{}
		err  bool
	}{
		{
			"exists",
			"test-kv-get/path",
			&NewNomadVariable(&nomadapi.Variable{
				Namespace: "default",
				Path:      "test-kv-get/path",
				Items: nomadapi.VariableItems{
					"bar": "barp",
				},
			}).Items,
			false,
		},
		{
			"no_exist",
			"test-kv-get/not/a/real/path/like/ever",
			nil,
			false,
		},
		{
			"exists_ns",
			"test-ns-get/path@test",
			&NewNomadVariable(&nomadapi.Variable{
				Namespace: "test",
				Path:      "test-ns-get/path",
				Items: nomadapi.VariableItems{
					"car": "carp",
				},
			}).Items,
			false,
		},
		{
			"exists_badregion",
			"test-ns-get/path@default.bad",
			fmt.Errorf("nomad.var.get(test-ns-get/path@default.bad): Unexpected response code: 500 (No path to region)"),
			true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNVGetQuery("", tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(testClients, nil)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if err != nil && tc.err {
				require.Equal(t, tc.exp.(error).Error(), err.Error())
				return
			}
			if tc.exp != nil {
				testNomadSVEquivalent(t, tc.exp, act)
			} else {
				assert.Nil(t, act)
			}
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewNVGetQuery("", "test-kv-get/path")
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
		case <-time.After(200 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	t.Run("fires_changes", func(t *testing.T) {
		d, err := NewNVGetQuery("", "test-kv-get/path")
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

		_ = testNomad.CreateVariable("test-kv-get/path", nvmap{"bar": "barp", "car": "carp"}, nil)

		select {
		case err := <-errCh:
			t.Fatal(err)
		case data := <-dataCh:
			exp := &(NewNomadVariable(&nomadapi.Variable{
				Namespace: "default",
				Path:      "test-kv-get/path",
				Items:     nomadapi.VariableItems{"bar": "barp", "car": "carp"},
			}).Items)
			testNomadSVEquivalent(t, exp, data)
		}
	})
}

func TestNVGetQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"path",
			"path",
			"nomad.var.get(path@default.global)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNVGetQuery("", tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}

func testNomadSVEquivalent(t *testing.T, expIf, actIf interface{}) {
	if expIf == nil && actIf == nil {
		return
	}
	if expIf == nil || actIf == nil {
		t.Fatalf("Mismatched nil and value.\na: %v\nb:%v", expIf, actIf)
	}
	exp, ok := expIf.(*NomadVarItems)
	require.True(t, ok, "exp is not *NomadVarItems, got %T", expIf)
	act, ok := actIf.(*NomadVarItems)
	require.True(t, ok, "act is not *NomadVarItems, got %T", actIf)

	expMeta := exp.Metadata()
	actMeta := act.Metadata()
	require.NotNil(t, expMeta, "Expected non-nil expMeta.Metadata()")
	require.NotNil(t, actMeta, "Expected non-nil intMeta.Metadata()")
	require.Equal(t, expMeta.Namespace, actMeta.Namespace)
	require.Equal(t, expMeta.Path, actMeta.Path)
	require.ElementsMatch(t, exp.Tuples(), act.Tuples())
}
