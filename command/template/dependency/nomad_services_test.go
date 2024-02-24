// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewNomadServicesQueryQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *NomadServicesQuery
		err  bool
	}{
		{
			"empty",
			"",
			&NomadServicesQuery{},
			false,
		},
		{
			"node",
			"node",
			nil,
			true,
		},
		{
			"region",
			"@us-east-1",
			&NomadServicesQuery{
				region: "us-east-1",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewNomadServicesQuery(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			require.Equal(t, tc.exp, act)
		})
	}
}

func TestNomadServicesQuery_Fetch_1arg(t *testing.T) {
	cases := []struct {
		name    string
		service string
		exp     []*NomadServicesSnippet
	}{
		{
			name:    "all",
			service: "",
			exp: []*NomadServicesSnippet{
				{
					Name: "example-cache",
					Tags: ServiceTags([]string{"tag1", "tag2"}),
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServicesQuery(tc.service)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, tc.exp, act)
		})
	}
}

func TestNomadServicesQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"empty",
			"",
			"nomad.services",
		},
		{
			"region",
			"@us-east-1",
			"nomad.services(@us-east-1)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServicesQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, tc.exp, d.String())
		})
	}
}
