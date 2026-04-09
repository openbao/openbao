package vault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	controlGroupRequestHelp   = `This endpoint will provide info about a token associated with the given accessor. Response will not contain the token ID. Only applicable when control-group policy resulted in wrapped response.`
	controlGroupAuthorizeHelp = `This endpoint will authorize a token associated with the given accessor. Response will not contain the token ID. Only applicable when control-group policy resulted in wrapped response.`
)

// controlGroupRequestResponseSchema defines the response schema for control group lookup.
// This schema is used both for OpenAPI generation and ensures handler consistency
var controlGroupRequestResponseSchema = map[string]*framework.FieldSchema{
	"approved": {
		Type:        framework.TypeBool,
		Description: "Status of the wrapping token",
		Required:    true,
	},
	"request_operation": {
		Type:        framework.TypeString,
		Description: "The original request operation",
		Required:    true,
	},
	"request_path": {
		Type:        framework.TypeString,
		Description: "The original request path",
		Required:    true,
	},
	"request_entity": {
		Type:        framework.TypeMap,
		Description: "The original requesting entity",
		Required:    true,
	},
	"authorizations": {
		Type:        framework.TypeSlice,
		Description: "The authorizations posted to this token",
		Required:    true,
	},
}

// controlGroupAuthorizeResponseSchema defines the response schema for control group authorization.
// This schema is used both for OpenAPI generation and ensures handler consistency
var controlGroupAuthorizeResponseSchema = map[string]*framework.FieldSchema{
	"approved": {
		Type:        framework.TypeBool,
		Description: "Status of the wrapping token",
		Required:    true,
	},
}

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

// getRequestFromTokenEntry fetchest original request from tokenEntry
func (c *Core) getRequestFromTokenEntry(ctx context.Context, tokenEntry *logical.TokenEntry) (*logical.Request, error) {
	reqBytes, ok := tokenEntry.InternalMeta["request"]
	if !ok {
		return nil, errors.New("token meta does not contain request")
	}

	var req logical.Request
	if err := jsonutil.DecodeJSON([]byte(reqBytes), &req); err != nil {
		return nil, err
	}

	return &req, nil
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
	controlGroup, ok := tokenEntry.InternalMeta["control_group"]
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

// getEnitityFromTokenEntry fetches entity from a token entry where present
func (c *Core) getEntityFromTokenEntry(ctx context.Context, tokenEntry *logical.TokenEntry) (*logical.Entity, error) {
	entityJson, ok := tokenEntry.InternalMeta["request_entity"]
	if !ok {
		// if there's no control group, nothing to return but it's not an error
		// nolint:nilnil
		return nil, nil
	}

	entity := logical.Entity{}
	if err := jsonutil.DecodeJSON([]byte(entityJson), &entity); err != nil {
		return nil, err
	}

	return &entity, nil
}

// setControlGroupInTokenEntry replaces the control group meta data on a given token entry
func (c *Core) setControlGroupInTokenEntry(ctx context.Context, tokenEntry *logical.TokenEntry, cg *logical.ControlGroup) error {
	cgJson, err := jsonutil.EncodeJSON(cg)
	if err != nil {
		return err
	}
	if tokenEntry.InternalMeta == nil {
		tokenEntry.InternalMeta = map[string]string{}
	}
	tokenEntry.InternalMeta["control_group"] = string(cgJson)
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
func (c *Core) validateControlGroup(ctx context.Context, tokenEntry *logical.TokenEntry, requestCapability logical.Operation) (bool, error) {
	cg, err := c.getControlGroupFromTokenEntry(ctx, tokenEntry)
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

// handleControlGroupRequest handles the sys/control-group/request path for querying information about
// a particular token. This can be used to see which policies are applicable.
func (c *Core) handleControlGroupRequest(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessor := data.Get("accessor").(string)
	if accessor == "" {
		return nil, &logical.StatusBadRequest{Err: "missing accessor"}
	}

	aEntry, err := c.tokenStore.lookupByAccessor(ctx, accessor, false, false)
	if err != nil {
		return nil, err
	}
	if aEntry == nil {
		return nil, &logical.StatusBadRequest{Err: "invalid accessor"}
	}

	out, err := c.tokenStore.lookupInternal(ctx, aEntry.TokenID, false, true)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if out == nil {
		return logical.ErrorResponse("bad token"), logical.ErrPermissionDenied
	}

	approved, err := c.validateControlGroup(ctx, out, logical.ReadOperation)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	originalRequest, err := c.getRequestFromTokenEntry(ctx, out)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	cg, err := c.getControlGroupFromTokenEntry(ctx, out)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	originalEntity, err := c.getEntityFromTokenEntry(ctx, out)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	// Generate a response.
	resp := &logical.Response{
		Data: map[string]interface{}{
			"approved":          approved,
			"request_operation": originalRequest.Operation,
			"request_path":      originalRequest.Path,
			"request_entity":    originalEntity,
			"authorizations":    cg.Factors[0].Authorizations,
		},
	}

	return resp, nil
}

// handleControlGroupAuthorize handles the sys/control-group/authorize path for authorizing
// a wrapped response token governed by a control-group policy.
func (c *Core) handleControlGroupAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessor := data.Get("accessor").(string)
	if accessor == "" {
		return nil, &logical.StatusBadRequest{Err: "missing accessor"}
	}

	aEntry, err := c.tokenStore.lookupByAccessor(ctx, accessor, false, false)
	if err != nil {
		return nil, err
	}
	if aEntry == nil {
		return nil, &logical.StatusBadRequest{Err: "invalid accessor"}
	}

	// Obtain identity info for the authorizer
	_, authorizerToken, _, _, err := c.fetchACLTokenEntryAndEntity(ctx, req)
	if err != nil {
		return nil, err
	}
	if authorizerToken == nil {
		return nil, &logical.StatusBadRequest{Err: "missing auth"}
	}
	authorizerGroups, err := c.identityStore.MemDBGroupsByMemberEntityID(ctx, authorizerToken.EntityID, false, false)
	if err != nil {
		return nil, err
	}
	authorizerGroupAliases := []*logical.Alias{}
	for _, group := range authorizerGroups {
		authorizerGroupAliases = append(authorizerGroupAliases, &logical.Alias{
			Name: group.Name,
		})
	}
	authorizerAuth := logical.Auth{
		DisplayName:  authorizerToken.DisplayName,
		GroupAliases: authorizerGroupAliases,
	}

	// Add authorization record to the token entry if applicable
	err = c.addAuthorization(ctx, aEntry.TokenID, &authorizerAuth)
	if err != nil {
		return nil, err
	}

	// Prepare the field data required for a lookup call
	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"accessor": accessor,
		},
		Schema: map[string]*framework.FieldSchema{
			"accessor": {
				Type:        framework.TypeString,
				Description: "Accessor to lookup control group state",
			},
		},
	}

	lookupResponse, err := c.handleControlGroupRequest(ctx, req, d)
	if err != nil {
		return nil, err
	}
	if lookupResponse == nil {
		return nil, errors.New("failed to lookup the token")
	}
	if lookupResponse.IsError() {
		return lookupResponse, nil
	}

	// Only return the "approved" information
	resp := logical.Response{
		Data: map[string]interface{}{
			"approved": lookupResponse.Data["approved"],
		},
	}

	return &resp, nil
}
