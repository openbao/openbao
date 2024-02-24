// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewKVKeysQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *KVKeysQuery
		err  bool
	}{
		{
			"empty",
			"",
			&KVKeysQuery{},
			false,
		},
		{
			"dc_only",
			"@dc1",
			nil,
			true,
		},
		{
			"query_only",
			"?ns=foo",
			nil,
			true,
		},
		{
			"invalid query param (unsupported key)",
			"prefix?unsupported=foo",
			nil,
			true,
		},
		{
			"prefix",
			"prefix",
			&KVKeysQuery{
				prefix: "prefix",
			},
			false,
		},
		{
			"dc",
			"prefix@dc1",
			&KVKeysQuery{
				prefix: "prefix",
				dc:     "dc1",
			},
			false,
		},
		{
			"partition",
			"prefix?partition=foo",
			&KVKeysQuery{
				prefix:    "prefix",
				partition: "foo",
			},
			false,
		},
		{
			"namespace",
			"prefix?ns=foo",
			&KVKeysQuery{
				prefix:    "prefix",
				namespace: "foo",
			},
			false,
		},
		{
			"namespace_and_partition",
			"prefix?ns=foo&partition=bar",
			&KVKeysQuery{
				prefix:    "prefix",
				namespace: "foo",
				partition: "bar",
			},
			false,
		},
		{
			"namespace_and_partition_and_dc",
			"prefix?ns=foo&partition=bar@dc1",
			&KVKeysQuery{
				prefix:    "prefix",
				namespace: "foo",
				partition: "bar",
				dc:        "dc1",
			},
			false,
		},
		{
			"empty_query",
			"prefix?ns=&partition=",
			&KVKeysQuery{
				prefix:    "prefix",
				namespace: "",
				partition: "",
			},
			false,
		},
		{
			"dots",
			"prefix.with.dots",
			&KVKeysQuery{
				prefix: "prefix.with.dots",
			},
			false,
		},
		{
			"slashes",
			"prefix/with/slashes",
			&KVKeysQuery{
				prefix: "prefix/with/slashes",
			},
			false,
		},
		{
			"dashes",
			"prefix-with-dashes",
			&KVKeysQuery{
				prefix: "prefix-with-dashes",
			},
			false,
		},
		{
			"leading_slash",
			"/leading/slash",
			&KVKeysQuery{
				prefix: "leading/slash",
			},
			false,
		},
		{
			"trailing_slash",
			"trailing/slash/",
			&KVKeysQuery{
				prefix: "trailing/slash/",
			},
			false,
		},
		{
			"underscores",
			"prefix_with_underscores",
			&KVKeysQuery{
				prefix: "prefix_with_underscores",
			},
			false,
		},
		{
			"special_characters",
			"config/facet:größe-lf-si",
			&KVKeysQuery{
				prefix: "config/facet:größe-lf-si",
			},
			false,
		},
		{
			"splat",
			"config/*/timeouts/",
			&KVKeysQuery{
				prefix: "config/*/timeouts/",
			},
			false,
		},
		{
			"slash",
			"/",
			&KVKeysQuery{
				prefix: "/",
			},
			false,
		},
		{
			"slash-slash",
			"//",
			&KVKeysQuery{
				prefix: "/",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewKVKeysQuery(tc.i)
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

func TestKVKeysQuery_Fetch(t *testing.T) {
	testConsul.SetKVString(t, "test-kv-keys/prefix/foo", "bar")
	testConsul.SetKVString(t, "test-kv-keys/prefix/zip", "zap")
	testConsul.SetKVString(t, "test-kv-keys/prefix/wave/ocean", "sleek")

	cases := []struct {
		name string
		i    string
		exp  []string
	}{
		{
			"exists",
			"test-kv-keys/prefix",
			[]string{"foo", "wave/ocean", "zip"},
		},
		{
			"trailing",
			"test-kv-keys/prefix/",
			[]string{"foo", "wave/ocean", "zip"},
		},
		{
			"no_exist",
			"test-kv-keys/not/a/real/prefix/like/ever",
			[]string{},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewKVKeysQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		d, err := NewKVKeysQuery("test-kv-keys/prefix")
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
		case <-time.After(100 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	t.Run("fires_changes", func(t *testing.T) {
		d, err := NewKVKeysQuery("test-kv-keys/prefix/")
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

		testConsul.SetKVString(t, "test-kv-keys/prefix/zebra", "value")

		select {
		case err := <-errCh:
			t.Fatal(err)
		case act := <-dataCh:
			exp := []string{"foo", "wave/ocean", "zebra", "zip"}
			assert.Equal(t, exp, act)
		}
	})
}

func TestKVKeysQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"prefix",
			"prefix",
			"kv.keys(prefix)",
		},
		{
			"dc",
			"prefix@dc1",
			"kv.keys(prefix@dc1)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewKVKeysQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
