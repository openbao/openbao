// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/assert"
)

func TestNewHealthServiceQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *HealthServiceQuery
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"dc_only",
			"@dc1",
			nil,
			true,
		},
		{
			"near_only",
			"~near",
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
			"query_only",
			"?ns=foo",
			nil,
			true,
		},
		{
			name: "invalid query param (unsupported key)",
			i:    "name?unsupported=test",
			err:  true,
		},
		{
			"name",
			"name",
			&HealthServiceQuery{
				filters: []string{"passing"},
				name:    "name",
			},
			false,
		},
		{
			"name_dc",
			"name@dc1",
			&HealthServiceQuery{
				dc:      "dc1",
				filters: []string{"passing"},
				name:    "name",
			},
			false,
		},
		{
			"name_dc_near",
			"name@dc1~near",
			&HealthServiceQuery{
				dc:      "dc1",
				filters: []string{"passing"},
				name:    "name",
				near:    "near",
			},
			false,
		},
		{
			"name_near",
			"name~near",
			&HealthServiceQuery{
				filters: []string{"passing"},
				name:    "name",
				near:    "near",
			},
			false,
		},
		{
			"tag_name",
			"tag.name",
			&HealthServiceQuery{
				filters: []string{"passing"},
				name:    "name",
				tag:     "tag",
			},
			false,
		},
		{
			"tag_name_dc",
			"tag.name@dc",
			&HealthServiceQuery{
				dc:      "dc",
				filters: []string{"passing"},
				name:    "name",
				tag:     "tag",
			},
			false,
		},
		{
			"tag_name_near",
			"tag.name~near",
			&HealthServiceQuery{
				filters: []string{"passing"},
				name:    "name",
				near:    "near",
				tag:     "tag",
			},
			false,
		},
		{
			"tag_name_dc_near",
			"tag.name@dc~near",
			&HealthServiceQuery{
				dc:      "dc",
				filters: []string{"passing"},
				name:    "name",
				near:    "near",
				tag:     "tag",
			},
			false,
		},
		{
			"name_partition",
			"name?partition=foo",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				name:      "name",
				partition: "foo",
			},
			false,
		},
		{
			"name_peer",
			"name?peer=foo",
			&HealthServiceQuery{
				filters: []string{"passing"},
				name:    "name",
				peer:    "foo",
			},
			false,
		},
		{
			"name_ns",
			"name?ns=foo",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				name:      "name",
				namespace: "foo",
			},
			false,
		},
		{
			"name_ns_peer_partition",
			"name?ns=foo&peer=bar&partition=baz",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				name:      "name",
				namespace: "foo",
				peer:      "bar",
				partition: "baz",
			},
			false,
		},
		{
			"namespace set twice should use first",
			"name?ns=foo&ns=bar",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				name:      "name",
				namespace: "foo",
			},
			false,
		},
		{
			"empty value in query param",
			"name?ns=&peer=&partition=",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				name:      "name",
				namespace: "",
				peer:      "",
				partition: "",
			},
			false,
		},
		{
			"query with other parameters",
			"tag.name?peer=foo&ns=bar&partition=baz@dc2~near",
			&HealthServiceQuery{
				filters:   []string{"passing"},
				tag:       "tag",
				name:      "name",
				dc:        "dc2",
				near:      "near",
				peer:      "foo",
				namespace: "bar",
				partition: "baz",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewHealthServiceQuery(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
	// Connect
	// all tests above also test connect, just need to check enabling it
	t.Run("connect_query", func(t *testing.T) {
		act, err := NewHealthConnectQuery("name")
		if err != nil {
			t.Fatal(err)
		}
		if act != nil {
			act.stopCh = nil
		}
		exp := &HealthServiceQuery{
			filters: []string{"passing"},
			name:    "name",
			connect: true,
		}

		assert.Equal(t, exp, act)
	})
}

func TestHealthConnectServiceQuery_Fetch(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  []*HealthService
	}{
		{
			"connect-service",
			"foo",
			[]*HealthService{
				{
					Name:        "foo-sidecar-proxy",
					ID:          "foo",
					Port:        21999,
					Status:      "passing",
					Address:     "127.0.0.1",
					NodeAddress: "127.0.0.1",
					Tags:        ServiceTags([]string{}),
					NodeMeta: map[string]string{
						"consul-network-segment": "",
					},
					Weights: api.AgentWeights{
						Passing: 1,
						Warning: 1,
					},
				},
			},
		},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewHealthConnectQuery(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				d.Stop()
			}()
			res, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}
			var act []*HealthService
			if act = res.([]*HealthService); len(act) != 1 {
				t.Fatal("Expected 1 result, got ", len(act))
			}
			// blank out fields we don't want to test
			inst := act[0]
			inst.Node, inst.NodeID = "", ""
			inst.Checks = nil
			inst.NodeTaggedAddresses = nil
			inst.ServiceTaggedAddresses = nil
			inst.NodeMeta = filterVersionMeta(inst.NodeMeta)

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestHealthServiceQuery_Fetch(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  []*HealthService
	}{
		{
			"consul",
			"consul",
			[]*HealthService{
				{
					Node:        testConsul.Config.NodeName,
					NodeAddress: testConsul.Config.Bind,
					NodeTaggedAddresses: map[string]string{
						"lan": "127.0.0.1",
						"wan": "127.0.0.1",
					},
					NodeMeta: map[string]string{
						"consul-network-segment": "",
					},
					ServiceMeta: map[string]string{},
					Address:     testConsul.Config.Bind,
					ID:          "consul",
					Name:        "consul",
					Tags:        []string{},
					Status:      "passing",
					Port:        testConsul.Config.Ports.Server,
					Weights: api.AgentWeights{
						Passing: 1,
						Warning: 1,
					},
				},
			},
		},
		{
			"filters",
			"consul|warning",
			[]*HealthService{},
		},
		{
			"multifilter",
			"consul|warning,passing",
			[]*HealthService{
				{
					Node:        testConsul.Config.NodeName,
					NodeAddress: testConsul.Config.Bind,
					NodeTaggedAddresses: map[string]string{
						"lan": "127.0.0.1",
						"wan": "127.0.0.1",
					},
					NodeMeta: map[string]string{
						"consul-network-segment": "",
					},
					ServiceMeta: map[string]string{},
					Address:     testConsul.Config.Bind,
					ID:          "consul",
					Name:        "consul",
					Tags:        []string{},
					Status:      "passing",
					Port:        testConsul.Config.Ports.Server,
					Weights: api.AgentWeights{
						Passing: 1,
						Warning: 1,
					},
				},
			},
		},
		{
			"service-meta",
			"service-meta",
			[]*HealthService{
				{
					Node:        testConsul.Config.NodeName,
					NodeAddress: testConsul.Config.Bind,
					NodeTaggedAddresses: map[string]string{
						"lan": "127.0.0.1",
						"wan": "127.0.0.1",
					},
					NodeMeta: map[string]string{
						"consul-network-segment": "",
					},
					ServiceMeta: map[string]string{
						"meta1": "value1",
					},
					Address: testConsul.Config.Bind,
					ID:      "service-meta",
					Name:    "service-meta",
					Tags:    []string{"tag1"},
					Status:  "passing",
					Weights: api.AgentWeights{
						Passing: 1,
						Warning: 1,
					},
				},
			},
		},
		{
			"service-taggedAddresses",
			"service-taggedAddresses",
			[]*HealthService{
				{
					Node:        testConsul.Config.NodeName,
					NodeAddress: testConsul.Config.Bind,
					NodeTaggedAddresses: map[string]string{
						"lan": "127.0.0.1",
						"wan": "127.0.0.1",
					},
					NodeMeta: map[string]string{
						"consul-network-segment": "",
					},
					ServiceMeta: map[string]string{},
					Address:     testConsul.Config.Bind,
					ServiceTaggedAddresses: map[string]api.ServiceAddress{
						"lan": {
							Address: "192.0.2.1",
							Port:    80,
						},
						"wan": {
							Address: "192.0.2.2",
							Port:    443,
						},
					},
					ID:     "service-taggedAddresses",
					Name:   "service-taggedAddresses",
					Tags:   []string{},
					Status: "passing",
					Weights: api.AgentWeights{
						Passing: 1,
						Warning: 1,
					},
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewHealthServiceQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(testClients, nil)
			if err != nil {
				t.Fatal(err)
			}

			if act != nil {
				for _, v := range act.([]*HealthService) {
					v.NodeID = ""
					v.Checks = nil
					// delete any version data from ServiceMeta
					v.ServiceMeta = filterVersionMeta(v.ServiceMeta)
					v.NodeTaggedAddresses = filterAddresses(
						v.NodeTaggedAddresses)
					v.NodeMeta = filterVersionMeta(v.NodeMeta)

				}
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestHealthServiceQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"name",
			"name",
			"health.service(name|passing)",
		},
		{
			"name_dc",
			"name@dc",
			"health.service(name@dc|passing)",
		},
		{
			"name_filter",
			"name|any",
			"health.service(name|any)",
		},
		{
			"name_multifilter",
			"name|warning,passing",
			"health.service(name|passing,warning)",
		},
		{
			"name_near",
			"name~near",
			"health.service(name~near|passing)",
		},
		{
			"name_near_filter",
			"name~near|any",
			"health.service(name~near|any)",
		},
		{
			"name_dc_near",
			"name@dc~near",
			"health.service(name@dc~near|passing)",
		},
		{
			"name_dc_near_filter",
			"name@dc~near|any",
			"health.service(name@dc~near|any)",
		},
		{
			"tag_name",
			"tag.name",
			"health.service(tag.name|passing)",
		},
		{
			"tag_name_dc",
			"tag.name@dc",
			"health.service(tag.name@dc|passing)",
		},
		{
			"tag_name_near",
			"tag.name~near",
			"health.service(tag.name~near|passing)",
		},
		{
			"tag_name_dc_near",
			"tag.name@dc~near",
			"health.service(tag.name@dc~near|passing)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewHealthServiceQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}

func TestHealthServiceQueryConnect_String(t *testing.T) {
	cases := []struct {
		name string
		fact func(string) (*HealthServiceQuery, error)
		in   string
		exp  string
	}{
		{
			"name",
			NewHealthServiceQuery,
			"name",
			"health.service(name|passing)",
		},
		{
			"name",
			NewHealthConnectQuery,
			"name",
			"health.connect(name|passing)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := tc.fact(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
