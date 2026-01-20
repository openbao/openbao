package vault

import (
	"context"
	"slices"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// makeLogicalControlGroup copies a vault.ControlGroup to a logical.ControlGroup
func makeLogicalControlGroup(authResultsControlGroup *ControlGroup) *logical.ControlGroup {
	if authResultsControlGroup == nil {
		return nil
	}

	cg := &logical.ControlGroup{
		TTL: authResultsControlGroup.TTL,
	}
	cg.Factors = make([]logical.ControlGroupFactor, len(authResultsControlGroup.Factors))
	for i, factor := range authResultsControlGroup.Factors {
		cg.Factors[i] = logical.ControlGroupFactor{
			Name:                   factor.Name,
			ControlledCapabilities: factor.ControlledCapabilities,
			Identity: logical.ControlGroupIdentity{
				GroupNames: factor.Identity.GroupNames,
				Approvals:  factor.Identity.Approvals,
			},
		}
	}
	return cg
}

// getControlGroup fetches control group from a token entry where present
func (c *Core) getControlGroup(ctx context.Context, token string) (*logical.ControlGroup, error) {
	tokenEntry, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		return nil, err
	}

	controlGroup, ok := tokenEntry.Meta["control_group"]
	if !ok {
		// if there's no control group, token is valid
		return nil, nil
	}

	cg := logical.ControlGroup{}
	if err := jsonutil.DecodeJSON([]byte(controlGroup), &cg); err != nil {
		return nil, err
	}

	return &cg, nil
}

// setControlGroup sets/replaces control group metadata on a token entry
func (c *Core) setControlGroup(ctx context.Context, token string, cg *logical.ControlGroup) error {
	tokenEntry, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		return err
	}
	if tokenEntry == nil {
		return nil
	}

	cgJson, err := jsonutil.EncodeJSON(cg)
	if err != nil {
		return err
	}
	if tokenEntry.Meta == nil {
		tokenEntry.Meta = map[string]string{}
	}
	tokenEntry.Meta["control_group"] = string(cgJson)
	return c.tokenStore.store(ctx, tokenEntry)
}

// validateControlGroup checks for a passing control group factor; passes if there is no control group config
func (c *Core) validateControlGroup(ctx context.Context, token string) (bool, error) {
	cg, err := c.getControlGroup(ctx, token)
	if err != nil {
		return false, err
	}
	// when no control group policy found, we pass this check
	if cg == nil {
		return true, nil
	}

	for _, factor := range cg.Factors {
		// count authorizations which have not expired
		approvalCount := 0
		for _, auth := range factor.Authorizations {
			if auth.Timestamp.Add(cg.TTL).After(time.Now()) {
				approvalCount++
			}
		}

		// any factor having approvalCount >= required approvals
		// will validate the token
		if approvalCount >= factor.Identity.Approvals {
			return true, nil
		}
	}
	return false, nil
}

// addAuthorization updates the control group metadata on the token with the given approval if applicable
func (c *Core) addAuthorization(ctx context.Context, token string, approver *logical.Auth) error {
	cg, err := c.getControlGroup(ctx, token)
	if err != nil {
		return err
	}

	// if there's no control group, no action taken but not an error
	if cg == nil {
		return nil
	}

	foundAuthorization := false
	for i, factor := range cg.Factors {
		identityGroups := factor.Identity.GroupNames
		for _, group := range approver.GroupAliases {
			if slices.Contains(identityGroups, group.Name) {
				foundAuthorization = true
				// TODO dedupe approvers
				// TODO make sure token doesn't have same identity as approver
				cg.Factors[i].Authorizations = append(factor.Authorizations, logical.ControlGroupAuthorization{
					Timestamp: time.Now(),
					Approver:  approver.DisplayName,
				})
			}
		}
	}

	if foundAuthorization {
		err = c.setControlGroup(ctx, token, cg)
		if err != nil {
			return err
		}
	}

	return nil
}
