package vault

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
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

// getControlGroup fetches control group from a token entry (where present) given a token
func (c *Core) getControlGroup(ctx context.Context, token string) (*logical.ControlGroup, error) {
	tokenEntry, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		return nil, err
	}
	return c.getControlGroupFromTokenEntry(ctx, tokenEntry)
}

// getControlGroupFromTokenEntry fetches control group from a token entry where present
func (c *Core) getControlGroupFromTokenEntry(ctx context.Context, tokenEntry *logical.TokenEntry) (*logical.ControlGroup, error) {
	controlGroup, ok := tokenEntry.Meta["control_group"]
	if !ok {
		// if there's no control group, nothing to return but it's not an error
		// nolint:nilnil
		return nil, nil
	}

	cg := logical.ControlGroup{}
	if err := jsonutil.DecodeJSON([]byte(controlGroup), &cg); err != nil {
		return nil, err
	}

	return &cg, nil
}

// setControlGroupInTokenEntry replaces the control group meta data on a given token entry
func (c *Core) setControlGroupInTokenEntry(ctx context.Context, tokenEntry *logical.TokenEntry, cg *logical.ControlGroup) error {
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

// setControlGroup sets/replaces control group metadata on a token entry
func (c *Core) setControlGroup(ctx context.Context, token string, cg *logical.ControlGroup) error {
	tokenEntry, err := c.tokenStore.Lookup(ctx, token)
	if err != nil {
		return err
	}
	if tokenEntry == nil {
		return nil
	}
	return c.setControlGroupInTokenEntry(ctx, tokenEntry, cg)
}

// validateControlGroup checks for a passing control group factor; passes if there is no control group config
func (c *Core) validateControlGroup(ctx context.Context, token string, requestCapability logical.Operation) (bool, error) {
	cg, err := c.getControlGroup(ctx, token)
	if err != nil {
		return false, err
	}
	// when no control group policy found, we pass this check
	if cg == nil {
		return true, nil
	}

	applicableControlGroups := 0
	passingControlGroups := 0
	for _, factor := range cg.Factors {

		// does factor apply? yes when ControlledCapabilities is nil or request operation matches
		if factor.ControlledCapabilities == nil ||
			slices.Contains(factor.ControlledCapabilities, requestCapability) {
			applicableControlGroups++
		} else {
			continue
		}

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
			passingControlGroups++
		}
	}
	if applicableControlGroups == passingControlGroups {
		return true, nil
	}

	return false, nil
}

// addAuthorization updates the control group metadata on the token with the given approval if applicable.
// rw lock is obtained and released during the operation.
func (c *Core) addAuthorization(ctx context.Context, token string, approver *logical.Auth) error {
	// obtain rw lock for the token
	lock := locksutil.LockForKey(c.tokenStore.tokenLocks, token)
	lock.Lock()
	defer lock.Unlock()

	tokenEntry, err := c.tokenStore.lookupInternal(ctx, token, false, false)
	if err != nil {
		return err
	}

	cg, err := c.getControlGroupFromTokenEntry(ctx, tokenEntry)
	if err != nil {
		return err
	}

	// if there's no control group, no action taken but not an error
	if cg == nil {
		return nil
	}

	addingAuthorization := false
	for i, factor := range cg.Factors {
		identityGroups := factor.Identity.GroupNames
		for _, group := range approver.GroupAliases {
			if slices.Contains(identityGroups, group.Name) {
				// make sure token doesn't have same identity as approver
				if tokenEntry.DisplayName == approver.DisplayName {
					return fmt.Errorf("token owner cannot be approver")
				}

				// make sure approver hasn't already approved
				for _, auth := range factor.Authorizations {
					if auth.Approver == approver.DisplayName {
						return fmt.Errorf("approver has already authorized")
					}
				}

				addingAuthorization = true
				cg.Factors[i].Authorizations = append(factor.Authorizations, logical.ControlGroupAuthorization{
					Timestamp: time.Now(),
					Approver:  approver.DisplayName,
				})
			}
		}
	}

	if addingAuthorization {
		err = c.setControlGroupInTokenEntry(ctx, tokenEntry, cg)
		if err != nil {
			return err
		}
	}

	return nil
}
