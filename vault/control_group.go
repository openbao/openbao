package vault

import (
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

// validateControlGroup checks for a passing factor
func validateControlGroup(controlGroup string) (bool, error) {
	cg := logical.ControlGroup{}
	if err := jsonutil.DecodeJSON([]byte(controlGroup), &cg); err != nil {
		return false, err
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
