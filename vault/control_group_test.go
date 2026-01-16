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

func TestControlGroup_setControlGroup(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	creationTime := time.Now()
	te := &logical.TokenEntry{
		Path:           "token/create",
		Policies:       []string{"response-wrapping"},
		CreationTime:   creationTime.Unix(),
		TTL:            time.Hour,
		NumUses:        3,
		ExplicitMaxTTL: time.Hour,
		NamespaceID:    "root",
		Meta: map[string]string{
			"ttl": "600s",
		},
	}

	ctx := namespace.RootContext(context.Background())
	testMakeTokenDirectly(t, ctx, c.tokenStore, te)
	require.NotEmpty(t, te.ID)                 // id has been created
	require.Empty(t, te.Meta["control_group"]) // no control group

	cg := logical.ControlGroup{
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

	// Set control group via token
	err := c.setControlGroup(ctx, te.ID, &cg)
	require.Nil(t, err)

	// Token entry should now have control group
	te, err = c.tokenStore.Lookup(ctx, te.ID)
	require.Nil(t, err)

	require.NotEmpty(t, te)
	require.NotEmpty(t, te.Meta["control_group"])
}

func TestControlGroup_addAuthorization(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	creationTime := time.Now()
	te := &logical.TokenEntry{
		Path:           "token/create",
		Policies:       []string{"response-wrapping"},
		CreationTime:   creationTime.Unix(),
		TTL:            time.Hour,
		NumUses:        3,
		ExplicitMaxTTL: time.Hour,
		NamespaceID:    "root",
		Meta: map[string]string{
			"ttl": "600s",
		},
	}

	ctx := namespace.RootContext(context.Background())
	testMakeTokenDirectly(t, ctx, c.tokenStore, te)
	require.NotEmpty(t, te.ID)                 // id has been created
	require.Empty(t, te.Meta["control_group"]) // no control group

	cg := logical.ControlGroup{
		TTL: time.Duration(14440),
		Factors: []logical.ControlGroupFactor{
			{
				Name: "test-secops",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"secops"},
					Approvals:  2,
				},
			},
			{
				Name: "test-admin",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"admin"},
					Approvals:  2,
				},
			},
			{
				Name: "test-both",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"admin", "secops"},
					Approvals:  2,
				},
			},
		},
	}

	// Set control group via token
	err := c.setControlGroup(ctx, te.ID, &cg)
	require.Nil(t, err)

	// addAuthorzation
	var groups []*logical.Alias
	groups = append(groups, &logical.Alias{
		Name: "secops",
	})
	auth := logical.Auth{
		GroupAliases: groups,
	}
	err = c.addAuthorization(ctx, te.ID, auth)

	// Token entry should now have the authorization
	cgFetched, err := c.getControlGroup(ctx, te.ID)

	// expect all matching factors to receive an authorization
	require.NotEmpty(t, cgFetched)
	require.Len(t, cgFetched.Factors[0].Authorizations, 1)
	require.Len(t, cgFetched.Factors[1].Authorizations, 0)
	require.Len(t, cgFetched.Factors[2].Authorizations, 1)
}

func TestControlGroup_validateControlGroup(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	creationTime := time.Now()
	te := &logical.TokenEntry{
		Path:           "token/create",
		Policies:       []string{"response-wrapping"},
		CreationTime:   creationTime.Unix(),
		TTL:            time.Hour,
		NumUses:        3,
		ExplicitMaxTTL: time.Hour,
		NamespaceID:    "root",
		Meta: map[string]string{
			"ttl": "600s",
		},
	}

	ctx := namespace.RootContext(context.Background())
	testMakeTokenDirectly(t, ctx, c.tokenStore, te)
	require.NotEmpty(t, te.ID)                 // id has been created
	require.Empty(t, te.Meta["control_group"]) // no control group

	cg := logical.ControlGroup{
		TTL: time.Duration(1 * time.Minute),
		Factors: []logical.ControlGroupFactor{
			{
				Name: "test-secops",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"secops"},
					Approvals:  2,
				},
			},
			{
				Name: "test-admin",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"admin"},
					Approvals:  2,
				},
			},
			{
				Name: "test-both",
				Identity: logical.ControlGroupIdentity{
					GroupNames: []string{"admin", "secops"},
					Approvals:  2,
				},
			},
		},
	}

	// Set control group via token
	err := c.setControlGroup(ctx, te.ID, &cg)
	require.Nil(t, err)

	// addAuthorzation
	var groups []*logical.Alias
	groups = append(groups, &logical.Alias{
		Name: "secops",
	})
	auth := logical.Auth{
		DisplayName:  "user@example.com",
		GroupAliases: groups,
	}
	err = c.addAuthorization(ctx, te.ID, auth)

	// Should not yet validate
	validates, err := c.validateControlGroup(ctx, te.ID)
	require.Nil(t, err)
	require.False(t, validates)

	// Second auth should permit validation
	err = c.addAuthorization(ctx, te.ID, auth)
	require.Nil(t, err)

	validates, err = c.validateControlGroup(ctx, te.ID)
	require.Nil(t, err)
	require.True(t, validates)
}
