// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCatalogServicesQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *CatalogServicesQuery
		err  bool
	}{
		{
			"empty",
			"",
			&CatalogServicesQuery{},
			false,
		},
		{
			"invalid query param (unsupported key)",
			"?unsupported=foo",
			nil,
			true,
		},
		{
			"node",
			"node",
			nil,
			true,
		},
		{
			"dc",
			"@dc1",
			&CatalogServicesQuery{
				dc: "dc1",
			},
			false,
		},
		{
			"namespace",
			"?ns=foo",
			&CatalogServicesQuery{
				namespace: "foo",
			},
			false,
		},
		{
			"partition",
			"?partition=foo",
			&CatalogServicesQuery{
				partition: "foo",
			},
			false,
		},
		{
			"partition_and_namespace",
			"?ns=foo&partition=bar",
			&CatalogServicesQuery{
				namespace: "foo",
				partition: "bar",
			},
			false,
		},
		{
			"partition_and_namespace_and_dc",
			"?ns=foo&partition=bar@dc1",
			&CatalogServicesQuery{
				namespace: "foo",
				partition: "bar",
				dc:        "dc1",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewCatalogServicesQuery(tc.i)
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

func TestCatalogServicesQuery_Fetch(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  []*CatalogSnippet
	}{
		{
			"all",
			"",
			[]*CatalogSnippet{
				{
					Name: "consul",
					Tags: ServiceTags([]string{}),
				},
				{
					Name: "foo-sidecar-proxy",
					Tags: ServiceTags([]string{}),
				},
				{
					Name: "service-meta",
					Tags: ServiceTags([]string{"tag1"}),
				},
				{
					Name: "service-taggedAddresses",
					Tags: ServiceTags([]string{}),
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewCatalogServicesQuery(tc.i)
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
}

func TestCatalogServicesQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"empty",
			"",
			"catalog.services",
		},
		{
			"datacenter",
			"@dc1",
			"catalog.services(@dc1)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewCatalogServicesQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
