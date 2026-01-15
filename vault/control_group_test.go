package vault

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestControlGroup_makeLogicalControlGroup(t *testing.T) {
	input := &ControlGroup{
		TTL: 14440,
		Factors: []ControlGroupFactor{{
			Name:                   "tester",
			ControlledCapabilities: []string{"create"},
			Identity: ControlGroupIdentity{
				GroupNames: []string{"admin"},
				Approvals:  2,
			}},
		},
	}
	output := makeLogicalControlGroup(input)
	require.IsType(t, logical.ControlGroup{}, *output)
	require.Equal(t, time.Duration(14440), output.TTL)
	require.Equal(t, "tester", output.Factors[0].Name)
	require.Equal(t, []string{"create"}, output.Factors[0].ControlledCapabilities)
	require.Equal(t, []string{"admin"}, output.Factors[0].Identity.GroupNames)

	output = makeLogicalControlGroup(nil)
	require.Empty(t, output)
}

func TestControlGroup_getControlGroup(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	ctx := namespace.RootContext(context.Background())
	originalCG := logical.ControlGroup{
		TTL: time.Duration(14440),
		Factors: []logical.ControlGroupFactor{
			{
				Name: "test-cg",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"secops"},
					Approvals:  2,
				},
			},
		},
	}

	cg, err := jsonutil.EncodeJSON(originalCG)
	require.Nil(t, err)

	creationTime := time.Now()
	te := logical.TokenEntry{
		Path:           "token/create",
		Policies:       []string{"response-wrapping"},
		CreationTime:   creationTime.Unix(),
		TTL:            time.Hour,
		NumUses:        3,
		ExplicitMaxTTL: time.Hour,
		NamespaceID:    "root",
		Meta: map[string]string{
			"ttl":           "600s",
			"control_group": string(cg),
		},
	}

	testMakeTokenDirectly(t, ctx, c.tokenStore, &te)
	require.NotEmpty(t, te.ID)

	// Fetch control group via token
	fetchedCG, err := c.getControlGroup(ctx, te.ID)
	require.Nil(t, err)
	require.Equal(t, &originalCG, fetchedCG)
}
