// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"testing"

	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestUnsafeCrossNamespaceIdentity(t *testing.T) {
	cases := []struct {
		parentNamespaced, childNamespaced bool
	}{
		{
			parentNamespaced: true,
			childNamespaced:  true,
		}, {
			parentNamespaced: true,
			childNamespaced:  false,
		}, {
			parentNamespaced: false,
			childNamespaced:  true,
		}, {
			parentNamespaced: false,
			childNamespaced:  false,
		},
	}

	for _, tc := range cases {
		name := ""
		if tc.parentNamespaced {
			name += "parent_namespaced"
		} else {
			name += "parent_root"
		}
		if tc.childNamespaced {
			name += "_child_namespaced"
		} else {
			name += "_child_root"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			coreConfig := &vault.CoreConfig{
				UnsafeCrossNamespaceIdentity: true,
				LogLevel:                     "debug",
			}
			cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
				HandlerFunc: vaulthttp.Handler,
				NumCores:    2,
			})
			cluster.Start()
			defer cluster.Cleanup()

			core := cluster.Cores[0].Core
			vault.TestWaitActive(t, core)
			client := cluster.Cores[0].Client
			client.SetCheckRedirect(nil)

			// create data

			t.Log("creating namespace")
			_, err := client.Logical().Write("sys/namespaces/test", map[string]any{})
			require.NoError(t, err)

			client.SetCloneToken(true)

			parentClient, err := client.Clone()
			require.NoError(t, err)
			if tc.parentNamespaced {
				parentClient.SetNamespace("test")
			}

			childClient, err := client.Clone()
			require.NoError(t, err)
			require.NoError(t, err)
			if tc.childNamespaced {
				childClient.SetNamespace("test")
			}

			t.Log("creating child")
			resp, err := childClient.Logical().Write("identity/group", map[string]any{
				"name": "child",
				"type": "external",
			})

			require.NoError(t, err)
			require.NotNil(t, resp)

			childId := resp.Data["id"]
			t.Logf("childId: %q", childId)

			t.Log("creating parent")
			resp, err = parentClient.Logical().Write("identity/group", map[string]any{
				"name":             "parent",
				"type":             "internal",
				"member_group_ids": childId,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			parentId := resp.Data["id"]
			t.Logf("parentId: %q", parentId)

			// verify

			verify := func() {
				resp, err = childClient.Logical().Read("identity/group/name/child")

				require.NoError(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)

				parentGroupIDs := resp.Data["parent_group_ids"]
				require.NotNil(t, parentGroupIDs)

				require.ElementsMatch(t, parentGroupIDs, []any{parentId})

				resp, err = parentClient.Logical().Read("identity/group/name/parent")

				require.NoError(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)

				memberGroupIDs := resp.Data["member_group_ids"]
				require.NotNil(t, memberGroupIDs)

				require.ElementsMatch(t, memberGroupIDs, []any{childId})
			}

			t.Log("verify")
			verify()

			// transfer leadership

			require.NoError(t, client.Sys().StepDown())
			t.Log("wait active again")
			vault.TestWaitActive(t, cluster.Cores[1].Core)

			// verify again

			t.Log("verify after leadership transfer")
			verify()
		})
	}
}
