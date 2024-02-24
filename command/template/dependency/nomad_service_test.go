// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNomadServiceQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *NomadServiceQuery
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"region_only",
			"@us-east-1",
			nil,
			true,
		},
		{
			"tag_only",
			"tag.",
			nil,
			true,
		},
		{
			"name",
			"name",
			&NomadServiceQuery{
				name: "name",
			},
			false,
		},
		{
			"name_region",
			"name@us-east-1",
			&NomadServiceQuery{
				region: "us-east-1",
				name:   "name",
			},
			false,
		},
		{
			"tag_name",
			"tag.name",
			&NomadServiceQuery{
				name: "name",
				tag:  "tag",
			},
			false,
		},
		{
			"tag_name_region",
			"tag.name@us-east-1",
			&NomadServiceQuery{
				region: "us-east-1",
				name:   "name",
				tag:    "tag",
			},
			false,
		},
		{
			"tag_name_with_colon",
			"tag:value.name",
			&NomadServiceQuery{
				name: "name",
				tag:  "tag:value",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewNomadServiceQuery(tc.i)
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

func TestNomadServiceChooseQuery(t *testing.T) {
	query, err := NewNomadServiceChooseQuery(4, "abc123", "tag.name@us-east-1")
	require.NoError(t, err)

	query.stopCh = nil
	require.Equal(t, &NomadServiceQuery{
		region: "us-east-1",
		name:   "name",
		tag:    "tag",
		choose: "4|abc123",
	}, query)
}

func TestNomadServiceQuery_Fetch(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  []*NomadService
	}{
		{
			"empty",
			"not-a-real-service",
			[]*NomadService{},
		},
		{
			"example_cache",
			"example-cache",
			[]*NomadService{
				{
					// ID is randomized so manually checked below
					Name: "example-cache",
					// Node is randomized so manually checked below
					Address: "127.0.0.1",
					// Port is randomized so manually checked below
					Datacenter: "dc1",
					Tags:       ServiceTags([]string{"tag1", "tag2"}),
					JobID:      "example",
					// AllocID is randomized so manually checked below
				},
			},
		},
		{
			"wrong_tag",
			"nope.example-cache",
			[]*NomadService{},
		},
		{
			"right_tag",
			"tag2.example-cache",
			[]*NomadService{
				{
					// ID is randomized so manually checked below
					Name: "example-cache",
					// Node is randomized so manually checked below
					Address: "127.0.0.1",
					// Port is randomized so manually checked below
					Datacenter: "dc1",
					Tags:       ServiceTags([]string{"tag1", "tag2"}),
					JobID:      "example",
					// AllocID is randomized so manually checked below
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServiceQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}

			actI, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			act := actI.([]*NomadService)

			for _, s := range act {
				// Assert the shape of the randomized fields
				assert.Regexp(t, "^_nomad-task.+", s.ID)
				assert.Regexp(t, ".+-.+-.+-.+-.+", s.Node)
				assert.NotZero(t, s.Port)
				assert.Regexp(t, ".+-.+-.+-.+-.+", s.AllocID)

				// Clear randomized fields
				s.ID = ""
				s.Node = ""
				s.Port = 0
				s.AllocID = ""
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestNomadServicesQuery_Fetch_3arg(t *testing.T) {
	cases := []struct {
		name    string
		service string
		count   int
		key     string
		exp     []*NomadService
	}{
		{
			name:    "choose one",
			service: "example-cache",
			count:   1,
			key:     "abc123",
			exp: []*NomadService{
				{
					Name:       "example-cache",
					Address:    "127.0.0.1",
					Datacenter: "dc1",
					Tags:       ServiceTags([]string{"tag1", "tag2"}),
					JobID:      "example",
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServiceChooseQuery(tc.count, tc.key, tc.service)
			if err != nil {
				t.Fatal(err)
			}

			actI, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			act := actI.([]*NomadService)

			for _, s := range act {
				// clear random fields
				s.ID = ""
				s.Node = ""
				s.Port = 0
				s.AllocID = ""
			}

			require.Equal(t, tc.exp, act)
		})
	}
}

func TestNomadServiceQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"name",
			"name",
			"nomad.service(name)",
		},
		{
			"name_region",
			"name@us-east-1",
			"nomad.service(name@us-east-1)",
		},
		{
			"tag_name",
			"tag.name",
			"nomad.service(tag.name)",
		},
		{
			"tag_name_region",
			"tag.name@us-east-1",
			"nomad.service(tag.name@us-east-1)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServiceQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, tc.exp, d.String())
		})
	}
}

func TestNomadServiceQuery_String_3arg(t *testing.T) {
	cases := []struct {
		name  string
		i     string
		count int
		key   string
		exp   string
	}{
		{
			"choose",
			"redis",
			3,
			"abc123",
			"nomad.service(redis:3|abc123)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewNomadServiceChooseQuery(3, "abc123", tc.i)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, tc.exp, d.String())
		})
	}
}
