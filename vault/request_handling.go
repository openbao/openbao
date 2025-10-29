// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/go-uuid"
	"google.golang.org/protobuf/proto"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/identity/mfa"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/internalshared/listenerutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/tokens"
)

const (
	replTimeout                           = 1 * time.Second
	EnvVaultDisableLocalAuthMountEntities = "BAO_DISABLE_LOCAL_AUTH_MOUNT_ENTITIES"

	// coreLockedUsersPath is a base path to store locked users
	coreLockedUsersPath = "core/login/lockedUsers/"
)

var (
	// DefaultMaxRequestDuration is the amount of time we'll wait for a request
	// to complete, unless overridden on a per-handler basis
	DefaultMaxRequestDuration = 90 * time.Second

	// DefaultMaxJsonMemory is the estimated amount of memory consumed by
	// the output representation of the JSON request body, unless overridden on
	// a per-listener basis.
	DefaultMaxJsonMemory = int64(32*1024*1024 + 512*1024)

	// DefaultMaxJsonStrings is the number of separate JSON strings
	// allowed in a request body, unless overridden on a per-listener basis.
	DefaultMaxJsonStrings = int64(1000)

	ErrNoApplicablePolicies = errors.New("no applicable policies")
	ErrPolicyNotExist       = errors.New("policy does not exist")

	// restrictedSysAPIs is the set of `sys/` APIs available only in the root namespace.
	restrictedSysAPIs = pathmanager.New()
)

func init() {
	restrictedSysAPIs.AddPaths([]string{
		"audit-hash",
		"audit",
		"config/auditing",
		"config/cors",
		"config/reload",
		"config/state",
		"config/ui",
		"decode-token",
		"generate-recovery-token",
		"generate-root",
		"health",
		"host-info",
		"in-flight-req",
		"init",
		"internal/counters/activity",
		"internal/counters/activity/export",
		"internal/counters/activity/monthly",
		"internal/counters/config",
		"internal/inspect/router",
		"key-status",
		"loggers",
		"managed-keys",
		"metrics",
		"mfa/method",
		"monitor",
		"pprof",
		"quotas/config",
		"quotas/lease-count",
		"quotas/rate-limit",
		"raw",
		"rekey-recovery-key",
		"rekey",
		"replication/merkle-check",
		"replication/recover",
		"replication/reindex",
		"replication/status",
		"rotate",
		"rotate/root",
		"rotate/config",
		"rotate/keyring",
		"rotate/keyring/config",
		"seal",
		"sealwrap/rewrap",
		"step-down",
		"storage",
		"sync/config",
		"unseal",
	})
}

// HandlerProperties is used to seed configuration into a vaulthttp.Handler.
// It's in this package to avoid a circular dependency
type HandlerProperties struct {
	Core                  *Core
	ListenerConfig        *configutil.Listener
	AllListeners          []listenerutil.Listener
	DisablePrintableCheck bool
	RecoveryMode          bool
	RecoveryToken         *atomic.Value
}

// fetchEntityAndDerivedPolicies returns the entity object for the given entity
// ID. If the entity is merged into a different entity object, the entity into
// which the given entity ID is merged into will be returned. This function
// also returns the cumulative list of policies that the entity is entitled to
// if skipDeriveEntityPolicies is set to false. This list includes the policies from the
// entity itself and from all the groups in which the given entity ID is a member of.
func (c *Core) fetchEntityAndDerivedPolicies(ctx context.Context, tokenNS *namespace.Namespace, entityID string, skipDeriveEntityPolicies bool) (*identity.Entity, map[string][]string, error) {
	if entityID == "" || c.identityStore == nil {
		return nil, nil, nil
	}

	// c.logger.Debug("entity set on the token", "entity_id", te.EntityID)

	// Fetch the entity
	nsCtx := namespace.ContextWithNamespace(ctx, tokenNS)
	entity, err := c.identityStore.MemDBEntityByID(nsCtx, entityID, false)
	if err != nil {
		c.logger.Error("failed to lookup entity using its ID", "error", err)
		return nil, nil, err
	}

	if entity == nil {
		// If there was no corresponding entity object found, it is
		// possible that the entity got merged into another entity. Try
		// finding entity based on the merged entity index.
		entity, err = c.identityStore.MemDBEntityByMergedEntityID(nsCtx, entityID, false)
		if err != nil {
			c.logger.Error("failed to lookup entity in merged entity ID index", "error", err)
			return nil, nil, err
		}
	}

	policies := make(map[string][]string)
	if entity != nil && !skipDeriveEntityPolicies {
		// c.logger.Debug("entity successfully fetched; adding entity policies to token's policies to create ACL")

		// Attach the policies on the entity
		if len(entity.Policies) != 0 {
			policies[entity.NamespaceID] = append(policies[entity.NamespaceID], entity.Policies...)
		}

		groupPolicies, err := c.identityStore.groupPoliciesByEntityID(nsCtx, entity.ID)
		if err != nil {
			c.logger.Error("failed to fetch group policies", "error", err)
			return nil, nil, err
		}

		policiesByNS, err := c.filterGroupPoliciesByNS(ctx, tokenNS, groupPolicies)
		if err != nil {
			return nil, nil, err
		}
		for nsID, pss := range policiesByNS {
			policies[nsID] = append(policies[nsID], pss...)
		}
	}

	return entity, policies, err
}

// filterGroupPoliciesByNS takes a context, token namespace, and a map of
// namespace IDs to slices of group policy names and returns a similar map,
// but filtered down to the policies that should apply to the token based on the
// relationship between the namespace of the token and the namespace of the
// policy.
func (c *Core) filterGroupPoliciesByNS(ctx context.Context, tokenNS *namespace.Namespace, groupPolicies map[string][]string) (map[string][]string, error) {
	policies := make(map[string][]string)

	policyApplicationMode, err := c.GetGroupPolicyApplicationMode(ctx)
	if err != nil {
		return nil, err
	}

	for nsID, nsPolicies := range groupPolicies {
		filteredPolicies, err := c.getApplicableGroupPolicies(ctx, tokenNS, nsID, nsPolicies, policyApplicationMode)
		if err != nil && err != ErrNoApplicablePolicies {
			return nil, err
		}
		filteredPolicies = strutil.RemoveDuplicates(filteredPolicies, true /* lowercase */)
		if len(filteredPolicies) != 0 {
			policies[nsID] = append(policies[nsID], filteredPolicies...)
		}
	}

	return policies, nil
}

// getApplicableGroupPolicies returns a slice of group policies that should
// apply to the token based on the group policy application mode,
// and the relationship between the token namespace and the group namespace.
func (c *Core) getApplicableGroupPolicies(ctx context.Context, tokenNS *namespace.Namespace, nsID string, nsPolicies []string, policyApplicationMode string) ([]string, error) {
	policyNS, err := c.NamespaceByID(ctx, nsID)
	if err != nil {
		return nil, err
	}
	if policyNS == nil {
		return nil, namespace.ErrNoNamespace
	}

	var filteredPolicies []string

	if tokenNS.Path == policyNS.Path {
		// Same namespace - add all and continue
		filteredPolicies = append(filteredPolicies, nsPolicies...)
		return filteredPolicies, nil
	}

	for _, policyName := range nsPolicies {
		policyNSCtx := namespace.ContextWithNamespace(ctx, policyNS)
		t, err := c.policyStore.GetNonEGPPolicyType(policyNSCtx, policyName)
		if err != nil && errors.Is(err, ErrPolicyNotExist) {
			// When we attempt to get a non-EGP policy type, and receive an
			// explicit error that it doesn't exist (in the type map) we log the
			// ns/policy and continue without error.
			c.Logger().Debug(fmt.Errorf("%w: %v/%v", err, policyNS.ID, policyName).Error())
			continue
		}
		if err != nil || t == nil {
			return nil, fmt.Errorf("failed to look up type of policy: %w", err)
		}

		switch *t {
		case PolicyTypeACL:
			if policyApplicationMode != groupPolicyApplicationModeWithinNamespaceHierarchy {
				// Group policy application mode isn't set to enforce
				// the namespace hierarchy, so apply all the ACLs,
				// regardless of their namespaces.
				filteredPolicies = append(filteredPolicies, policyName)
				continue
			}
			if policyNS.HasParent(tokenNS) {
				filteredPolicies = append(filteredPolicies, policyName)
			}
		default:
			return nil, fmt.Errorf("unexpected policy type: %v", t)
		}
	}
	if len(filteredPolicies) == 0 {
		return nil, ErrNoApplicablePolicies
	}
	return filteredPolicies, nil
}

func (c *Core) fetchACLTokenEntryAndEntity(ctx context.Context, req *logical.Request) (*ACL, *logical.TokenEntry, *identity.Entity, map[string][]string, error) {
	defer metrics.MeasureSince([]string{"core", "fetch_acl_and_token"}, time.Now())

	// Ensure there is a client token
	if req.ClientToken == "" {
		return nil, nil, nil, nil, logical.ErrPermissionDenied
	}

	if c.tokenStore == nil && req.TokenEntry() == nil {
		c.logger.Error("token store is unavailable")
		return nil, nil, nil, nil, ErrInternalError
	}

	// Resolve the token policy
	var te *logical.TokenEntry
	switch req.TokenEntry() {
	case nil:
		var err error
		te, err = c.tokenStore.Lookup(ctx, req.ClientToken)
		if err != nil {
			c.logger.Error("failed to lookup acl token", "error", err)
			return nil, nil, nil, nil, ErrInternalError
		}
		// Set the token entry here since it has not been cached yet
		req.SetTokenEntry(te)
	default:
		te = req.TokenEntry()
	}

	// Ensure the token is valid
	if te == nil {
		return nil, nil, nil, nil, logical.ErrPermissionDenied
	}

	// CIDR checks bind all tokens except non-expiring root tokens
	if te.TTL != 0 && len(te.BoundCIDRs) > 0 {
		var valid bool
		remoteSockAddr, err := sockaddr.NewSockAddr(req.Connection.RemoteAddr)
		if err != nil {
			if c.Logger().IsDebug() {
				c.Logger().Debug("could not parse remote addr into sockaddr", "error", err, "remote_addr", req.Connection.RemoteAddr)
			}
			return nil, nil, nil, nil, logical.ErrPermissionDenied
		}
		for _, cidr := range te.BoundCIDRs {
			if cidr.Contains(remoteSockAddr) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, nil, nil, nil, logical.ErrPermissionDenied
		}
	}

	policyNames := make(map[string][]string)
	// Add tokens policies
	policyNames[te.NamespaceID] = append(policyNames[te.NamespaceID], te.Policies...)

	tokenNS, err := c.NamespaceByID(ctx, te.NamespaceID)
	if err != nil {
		c.logger.Error("failed to fetch token namespace", "error", err)
		return nil, nil, nil, nil, ErrInternalError
	}
	if tokenNS == nil {
		c.logger.Error("failed to fetch token namespace", "error", namespace.ErrNoNamespace)
		return nil, nil, nil, nil, ErrInternalError
	}

	// Add identity policies from all the namespaces
	entity, identityPolicies, err := c.fetchEntityAndDerivedPolicies(ctx, tokenNS, te.EntityID, te.NoIdentityPolicies)
	if err != nil {
		return nil, nil, nil, nil, ErrInternalError
	}
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}

	// Attach token's namespace information to the context. Wrapping tokens by
	// should be able to be used anywhere, so we also special case behavior.
	var tokenCtx context.Context
	if len(policyNames) == 1 &&
		len(policyNames[te.NamespaceID]) == 1 &&
		policyNames[te.NamespaceID][0] == responseWrappingPolicyName &&
		(strings.HasSuffix(req.Path, "sys/wrapping/unwrap") ||
			strings.HasSuffix(req.Path, "sys/wrapping/lookup") ||
			strings.HasSuffix(req.Path, "sys/wrapping/rewrap")) {
		// Use the request namespace; will find the copy of the policy for the
		// local namespace
		tokenCtx = ctx
	} else {
		// Use the token's namespace for looking up policy
		tokenCtx = namespace.ContextWithNamespace(ctx, tokenNS)
	}

	// Add the inline policy if it's set
	policies := make([]*Policy, 0)
	if te.InlinePolicy != "" {
		inlinePolicy, err := ParseACLPolicy(tokenNS, te.InlinePolicy)
		if err != nil {
			return nil, nil, nil, nil, ErrInternalError
		}
		policies = append(policies, inlinePolicy)
	}

	// Construct the corresponding ACL object. ACL construction should be
	// performed on the token's namespace.
	acl, err := c.policyStore.ACL(tokenCtx, entity, policyNames, policies...)
	if err != nil {
		c.logger.Error("failed to construct ACL", "error", err)
		return nil, nil, nil, nil, ErrInternalError
	}

	return acl, te, entity, identityPolicies, nil
}

func (c *Core) CheckToken(ctx context.Context, req *logical.Request, unauth bool) (*logical.Auth, *ACL, *logical.TokenEntry, *identity.Entity, error) {
	defer metrics.MeasureSince([]string{"core", "check_token"}, time.Now())

	var acl *ACL
	var te *logical.TokenEntry
	var entity *identity.Entity
	var identityPolicies map[string][]string

	// Even if unauth, if a token is provided, there's little reason not to
	// gather as much info as possible for the audit log and to e.g. control
	// trace mode for EGPs.
	if !unauth || (unauth && (req.ClientToken != "" || req.HasInlineAuth)) {
		var err error
		acl, te, entity, identityPolicies, err = c.fetchACLTokenEntryAndEntity(ctx, req)
		// In the unauth case we don't want to fail the command, since it's
		// unauth, we just have no information to attach to the request, so
		// ignore errors...this was best-effort anyways
		if err != nil && !unauth {
			if c.standby {
				return nil, acl, te, entity, logical.ErrPerfStandbyPleaseForward
			}
			return nil, acl, te, entity, err
		}
	}

	if entity != nil && entity.Disabled {
		c.logger.Warn("permission denied as the entity on the token is disabled")
		return nil, acl, te, entity, logical.ErrPermissionDenied
	}
	if te != nil && te.EntityID != "" && entity == nil {
		if c.standby {
			return nil, acl, te, entity, logical.ErrPerfStandbyPleaseForward
		}
		c.logger.Warn("permission denied as the entity on the token is invalid")
		return nil, acl, te, entity, logical.ErrPermissionDenied
	}

	// Check if this is a root protected path
	rootPath := c.router.RootPath(ctx, req.Path)

	if rootPath && unauth {
		return nil, nil, nil, nil, errors.New("cannot access root path in unauthenticated request")
	}

	// At this point we won't be forwarding a raw request; we should delete
	// authorization headers as appropriate
	switch req.ClientTokenSource {
	case logical.ClientTokenFromVaultHeader:
		delete(req.Headers, consts.AuthHeaderName)
	case logical.ClientTokenFromAuthzHeader:
		if headers, ok := req.Headers["Authorization"]; ok {
			retHeaders := make([]string, 0, len(headers))
			for _, v := range headers {
				if strings.HasPrefix(v, "Bearer ") {
					continue
				}
				retHeaders = append(retHeaders, v)
			}
			req.Headers["Authorization"] = retHeaders
		}
	case logical.ClientTokenFromInlineAuth:
		delete(req.Headers, consts.InlineAuthPathHeaderName)
		delete(req.Headers, consts.InlineAuthOperationHeaderName)
		for header := range req.Headers {
			if !strings.HasPrefix(header, consts.InlineAuthParameterHeaderPrefix) {
				delete(req.Headers, header)
			}
		}
	}

	// When we receive a write of either type, rather than require clients to
	// PUT/POST and trust the operation, we ask the backend to give us the real
	// skinny -- if the backend implements an existence check, it can tell us
	// whether a particular resource exists. Then we can mark it as an update
	// or creation as appropriate.
	if req.Operation == logical.CreateOperation || req.Operation == logical.UpdateOperation {
		existsResp, checkExists, resourceExists, err := c.router.RouteExistenceCheck(ctx, req)
		switch err {
		case logical.ErrUnsupportedPath:
			// fail later via bad path to avoid confusing items in the log
			checkExists = false
		case logical.ErrRelativePath:
			return nil, acl, te, entity, errutil.UserError{Err: err.Error()}
		case nil:
			if existsResp != nil && existsResp.IsError() {
				return nil, acl, te, entity, existsResp.Error()
			}
			// Otherwise, continue on
		default:
			c.logger.Error("failed to run existence check", "error", err)
			if _, ok := err.(errutil.UserError); ok {
				return nil, acl, te, entity, err
			} else {
				return nil, acl, te, entity, ErrInternalError
			}
		}

		switch {
		case !checkExists:
			// No existence check, so always treat it as an update operation, which is how it is pre 0.5
			req.Operation = logical.UpdateOperation
		case resourceExists:
			// It exists, so force an update operation
			req.Operation = logical.UpdateOperation
		case !resourceExists:
			// It doesn't exist, force a create operation
			req.Operation = logical.CreateOperation
		default:
			panic("unreachable code")
		}
	}
	// Create the auth response
	auth := &logical.Auth{
		ClientToken: req.ClientToken,
		Accessor:    req.ClientTokenAccessor,
	}

	var clientID string
	if te != nil {
		auth.IdentityPolicies = identityPolicies[te.NamespaceID]
		auth.TokenPolicies = te.Policies
		auth.Policies = policyutil.SanitizePolicies(append(te.Policies, identityPolicies[te.NamespaceID]...), false)
		auth.Metadata = te.Meta
		auth.DisplayName = te.DisplayName
		auth.EntityID = te.EntityID
		delete(identityPolicies, te.NamespaceID)
		auth.ExternalNamespacePolicies = identityPolicies
		// Store the entity ID in the request object
		req.EntityID = te.EntityID
		auth.TokenType = te.Type
		auth.TTL = te.TTL
		if te.CreationTime > 0 {
			auth.IssueTime = time.Unix(te.CreationTime, 0)
		}
		clientID, _ = te.CreateClientID()
		req.ClientID = clientID
	}

	// Check the standard non-root ACLs. Return the token entry if it's not
	// allowed so we can decrement the use count.
	authResults := c.performPolicyChecks(ctx, acl, te, req, entity, &PolicyCheckOpts{
		Unauth:            unauth,
		RootPrivsRequired: rootPath,
	})

	auth.PolicyResults = &logical.PolicyResults{
		Allowed: authResults.Allowed,
	}

	if authResults.ACLResults != nil {
		auth.ResponseKeysFilterPath = authResults.ACLResults.ResponseKeysFilterPath
	}

	if !authResults.Allowed {
		retErr := authResults.Error

		if authResults.Error.ErrorOrNil() == nil || authResults.DeniedError {
			retErr = multierror.Append(retErr, logical.ErrPermissionDenied)
		}
		return auth, acl, te, entity, retErr
	}

	if authResults.ACLResults != nil && len(authResults.ACLResults.GrantingPolicies) > 0 {
		auth.PolicyResults.GrantingPolicies = authResults.ACLResults.GrantingPolicies
	}
	if authResults.SentinelResults != nil && len(authResults.SentinelResults.GrantingPolicies) > 0 {
		auth.PolicyResults.GrantingPolicies = append(auth.PolicyResults.GrantingPolicies, authResults.SentinelResults.GrantingPolicies...)
	}

	return auth, acl, te, entity, nil
}

// HandleRequest is used to handle a new incoming request
func (c *Core) HandleRequest(httpCtx context.Context, req *logical.Request) (resp *logical.Response, err error) {
	return c.switchedLockHandleRequest(httpCtx, req, true)
}

func (c *Core) switchedLockHandleRequest(httpCtx context.Context, req *logical.Request, doLocking bool) (resp *logical.Response, err error) {
	if doLocking {
		c.stateLock.RLock()
		defer c.stateLock.RUnlock()
	}
	if c.Sealed() {
		return nil, consts.ErrSealed
	}

	if c.activeContext == nil || c.activeContext.Err() != nil {
		return nil, errors.New("active context canceled after getting state lock")
	}

	ctx, cancel := context.WithCancel(c.activeContext)
	go func(ctx context.Context, httpCtx context.Context) {
		select {
		case <-ctx.Done():
		case <-httpCtx.Done():
			cancel()
		}
	}(ctx, httpCtx)

	// A namespace was manually passed to HandleRequest, as can be the case with:
	// 1. Synthesized logical requests not originating from an HTTP request
	// 2. Tests
	ns, err := namespace.FromContext(httpCtx)
	var nsHeader string
	if err != nil {
		// If the above is not the case, resolve the namespace from header & request path.
		nsHeader = namespace.HeaderFromContext(httpCtx)
		ns, req.Path = c.namespaceStore.ResolveNamespaceFromRequest(nsHeader, req.Path)
		if ns == nil {
			return nil, logical.CodedError(http.StatusNotFound, "namespace not found")
		}
	}

	if ns.ID != namespace.RootNamespaceID {
		// verify whether the namespace is either directly or inherently locked
		lockedNS := c.namespaceStore.GetLockingNamespace(ns)
		if lockedNS != nil && req.Operation != logical.RevokeOperation && req.Operation != logical.RollbackOperation {
			switch req.Path {
			case "sys/namespaces/api-lock/unlock":
			default:
				return logical.ErrorResponse("API access to this namespace has been locked by an administrator - %q must be unlocked to gain access.", lockedNS.Path), logical.ErrLockedNamespace
			}
		}

		if strings.HasPrefix(req.Path, "sys/") &&
			restrictedSysAPIs.HasPathSegments(req.Path[len("sys/"):]) {
			return nil, logical.CodedError(http.StatusBadRequest, "operation unavailable in namespaces")
		}
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)

	inFlightReqID, ok := httpCtx.Value(logical.CtxKeyInFlightRequestID{}).(string)
	if ok {
		ctx = context.WithValue(ctx, logical.CtxKeyInFlightRequestID{}, inFlightReqID)
	}
	requestRole, ok := httpCtx.Value(logical.CtxKeyRequestRole{}).(string)
	if ok {
		ctx = context.WithValue(ctx, logical.CtxKeyRequestRole{}, requestRole)
	}
	body, ok := logical.ContextOriginalBodyValue(httpCtx)
	if ok {
		ctx = logical.CreateContextOriginalBody(ctx, body)
	}

	// Perform inline authentication. This returns nil, nil if the request
	// succeeds and the passed request is mutated to now have the token. In
	// the event it fails, it may have either a request, an error, or both,
	// depending on what the auth method does.
	if resp, err := c.handleInlineAuth(ctx, req, nsHeader); err != nil || resp != nil {
		if err != nil {
			err = fmt.Errorf("failed to perform inline authentication: %w", err)
		}

		return resp, err
	}
	resp, err = c.handleCancelableRequest(ctx, req)
	req.SetTokenEntry(nil)
	cancel()
	return resp, err
}

func (c *Core) handleInlineAuth(ctx context.Context, req *logical.Request, nsHeader string) (*logical.Response, error) {
	// Find the path of the request.
	authPath, present := req.Headers[consts.InlineAuthPathHeaderName]
	if !present {
		return nil, nil
	}
	if len(authPath) != 1 {
		return nil, fmt.Errorf("expected exactly one value for %v", consts.InlineAuthPathHeaderName)
	}

	if req.ClientToken != "" {
		return nil, fmt.Errorf("cannot layer inline authentication with token authentication")
	}

	// Build an entirely new request; this will be executed before req
	requestId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identifier for the inline authentication request: %w", err)
	}

	authReq := &logical.Request{
		ID:           requestId,
		Path:         authPath[0],
		Storage:      req.Storage,
		Connection:   req.Connection,
		Headers:      req.Headers,
		MFACreds:     req.MFACreds,
		IsInlineAuth: true,
	}

	// Remove MFA credentials from the main request.
	req.MFACreds = nil

	// Find the optional operation; this defaults to Update if missing.
	authOperation, present := req.Headers[consts.InlineAuthOperationHeaderName]
	if !present {
		authOperation = []string{string(logical.UpdateOperation)}
	}
	if len(authOperation) != 1 {
		return nil, fmt.Errorf("expected exactly one value for %v", consts.InlineAuthOperationHeaderName)
	}
	authReq.Operation = logical.Operation(authOperation[0])

	// Find the optional namespace header; this defaults to X-Vault-Namespace
	// if missing.
	authNamespace, present := req.Headers[consts.InlineAuthNamespaceHeaderName]
	switch {
	case !present:
		authNamespace = []string{nsHeader}
	case len(authNamespace) == 0:
		authNamespace = []string{""}
	case len(authNamespace) > 1:
		return nil, fmt.Errorf("expected at most one value for %v", consts.InlineAuthNamespaceHeaderName)
	}

	var authNs *namespace.Namespace
	authNs, authReq.Path = c.namespaceStore.ResolveNamespaceFromRequest(authNamespace[0], authReq.Path)
	if authNs == nil {
		return nil, fmt.Errorf("inline auth namespace was not found")
	}

	authCtx := namespace.ContextWithNamespace(ctx, authNs)

	// Find all login request parameters. Usually we have at least two
	// parameters: a token of some sort and a role. This becomes our request
	// data.
	loginParams := make(map[string]interface{}, 2)
	for header, values := range req.Headers {
		if !strings.HasPrefix(header, consts.InlineAuthParameterHeaderPrefix) {
			continue
		}

		if len(values) != 1 {
			return nil, fmt.Errorf("expected exactly one value for each auth header parameter")
		}

		encodedHeader, err := base64.RawURLEncoding.DecodeString(values[0])
		if err != nil {
			return nil, fmt.Errorf("failed raw url-safe base64 decoding header value")
		}

		var paramInfo map[string]interface{}
		if err := json.Unmarshal(encodedHeader, &paramInfo); err != nil {
			return nil, errors.New("failed json decoding header value")
		}

		paramKeyRaw, present := paramInfo["key"]
		if !present {
			return nil, errors.New("decoded header lacked `key` field")
		}
		paramKey, ok := paramKeyRaw.(string)
		if !ok {
			return nil, errors.New("decoded header had incorrect type for `key` field")
		}

		paramValue, present := paramInfo["value"]
		if !present {
			return nil, errors.New("decoded header lacked `value` field")
		}

		if len(paramInfo) != 2 {
			return nil, errors.New("unexpected field in decoded request parameter")
		}

		loginParams[paramKey] = paramValue
	}

	authReq.Data = loginParams

	// Perform authentication but do not persist the underlying token. We
	// want to return the response from inline authentication if it is
	// relevant.
	resp, err := c.handleCancelableRequest(authCtx, authReq)
	if err != nil || resp == nil || resp.Auth == nil {
		// If we have a non-error response object, ensure it has a header
		// indicating it is from the auth step.
		if resp != nil {
			if resp.Headers == nil {
				resp.Headers = make(map[string][]string)
			}
			resp.Headers[consts.InlineAuthErrorResponseHeader] = []string{"true"}
		}

		// We could hit a case where err == resp == nil; set error to 404 not
		// found explicitly.
		if err == nil && resp == nil {
			err = logical.CodedError(http.StatusNotFound, "specified authentication path was not found")
		}

		return resp, err
	}

	// Now extract the token from the response and set it on our original
	// request.
	req.ClientToken = resp.Auth.ClientToken
	req.ClientTokenSource = logical.ClientTokenFromInlineAuth

	req.HasInlineAuth = true
	req.InlineAuth = resp.Auth
	req.SetTokenEntry(resp.InlineAuthTokenEntry)

	// Explicitly do not return the authentication request; the auth request
	// is only returned when it fails so it can be sent to the client.
	return nil, nil
}

func (c *Core) handleCancelableRequest(ctx context.Context, req *logical.Request) (resp *logical.Response, err error) {
	// Allowing writing to a path ending in / makes it extremely difficult to
	// understand user intent for the filesystem-like backends (kv,
	// cubbyhole) -- did they want a key named foo/ or did they want to write
	// to a directory foo/ with no (or forgotten) key, or...? It also affects
	// lookup, because paths ending in / are considered prefixes by some
	// backends. Basically, it's all just terrible, so don't allow it.
	if strings.HasSuffix(req.Path, "/") &&
		(req.Operation == logical.UpdateOperation ||
			req.Operation == logical.CreateOperation ||
			req.Operation == logical.PatchOperation) {
		return logical.ErrorResponse("cannot write to a path ending in '/'"), nil
	}

	// MountPoint will not always be set at this point, so we ensure the req contains it
	// as it is depended on by some functionality (e.g. quotas)
	req.MountPoint = c.router.MatchingMount(ctx, req.Path)

	err = c.PopulateTokenEntry(ctx, req)
	if err != nil {
		return nil, err
	}

	// Always forward requests that are using a limited use count token.
	if c.standby && req.ClientTokenRemainingUses > 0 {
		// Prevent forwarding on local-only requests.
		return nil, logical.ErrPerfStandbyPleaseForward
	}

	var requestBodyToken string
	var returnRequestAuthToken bool

	// req.Path will be relative by this point. The prefix check is first
	// to fail faster if we're not in this situation since it's a hot path
	switch {
	case strings.HasPrefix(req.Path, "sys/wrapping/"), strings.HasPrefix(req.Path, "auth/token/"):
		// Get the token ns info; if we match the paths below we want to
		// swap in the token context (but keep the relative path)
		te := req.TokenEntry()
		newCtx := ctx
		if te != nil {
			ns, err := c.NamespaceByID(ctx, te.NamespaceID)
			if err != nil {
				c.Logger().Warn("error looking up namespace from the token's namespace ID", "error", err)
				return nil, err
			}
			if ns != nil {
				newCtx = namespace.ContextWithNamespace(ctx, ns)
			}
		}
		switch req.Path {
		// Route the token wrapping request to its respective sys NS
		case "sys/wrapping/lookup", "sys/wrapping/rewrap", "sys/wrapping/unwrap":
			ctx = newCtx
			// A lookup on a token that is about to expire returns nil, which means by the
			// time we can validate a wrapping token lookup will return nil since it will
			// be revoked after the call. So we have to do the validation here.
			valid, err := c.validateWrappingToken(ctx, req)
			if err != nil {
				return logical.ErrorResponse("error validating wrapping token: %s", err.Error()), logical.ErrPermissionDenied
			}
			if !valid {
				return nil, consts.ErrInvalidWrappingToken
			}

		// The -self paths have no meaning outside of the token NS, so
		// requests for these paths always go to the token NS
		case "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self":
			ctx = newCtx
			returnRequestAuthToken = true

		// For the following operations, we can set the proper namespace context
		// using the token's embedded nsID if a relative path was provided.
		// The operation will still be gated by ACLs, which are checked later.
		case "auth/token/lookup", "auth/token/renew", "auth/token/revoke", "auth/token/revoke-orphan":
			token, ok := req.Data["token"]
			// If the token is not present (e.g. a bad request), break out and let the backend
			// handle the error
			if !ok {
				// If this is a token lookup request and if the token is not
				// explicitly provided, it will use the client token so we simply set
				// the context to the client token's context.
				if req.Path == "auth/token/lookup" {
					ctx = newCtx
				}
				break
			}
			if token == nil {
				return logical.ErrorResponse("invalid token"), logical.ErrPermissionDenied
			}
			// We don't care if the token is a server side consistent token or not. Either way, we're going
			// to be returning it for these paths instead of the short token stored in vault.
			requestBodyToken = token.(string)
			if IsSSCToken(token.(string)) {
				token, err = c.CheckSSCToken(ctx, token.(string), c.isLoginRequest(ctx, req))
				// If we receive an error from CheckSSCToken, we can assume the token is bad somehow, and the client
				// should receive a 403 bad token error like they do for all other invalid tokens, unless the error
				// specifies that we should forward the request or retry the request.
				if err != nil {
					if logical.ShouldForward(err) {
						return nil, err
					}
					return logical.ErrorResponse("bad token"), logical.ErrPermissionDenied
				}
				req.Data["token"] = token
			}
			_, nsID := namespace.SplitIDFromString(token.(string))
			if nsID != "" {
				ns, err := c.NamespaceByID(ctx, nsID)
				if err != nil {
					c.Logger().Warn("error looking up namespace from the token's namespace ID", "error", err)
					return nil, err
				}
				if ns != nil {
					ctx = namespace.ContextWithNamespace(ctx, ns)
				}
			}
		}

	// The following relative sys/leases/ paths handles re-routing requests
	// to the proper namespace using the lease ID on applicable paths.
	case strings.HasPrefix(req.Path, "sys/leases/"):
		switch req.Path {
		// For the following operations, we can set the proper namespace context
		// using the lease's embedded nsID if a relative path was provided.
		// The operation will still be gated by ACLs, which are checked later.
		case "sys/leases/lookup", "sys/leases/renew", "sys/leases/revoke", "sys/leases/revoke-force":
			leaseID, ok := req.Data["lease_id"]
			// If lease ID is not present, break out and let the backend handle the error
			if !ok || leaseID == nil {
				break
			}
			_, nsID := namespace.SplitIDFromString(leaseID.(string))
			if nsID != "" {
				ns, err := c.NamespaceByID(ctx, nsID)
				if err != nil {
					c.Logger().Warn("error looking up namespace from the lease's namespace ID", "error", err)
					return nil, err
				}
				if ns != nil {
					ctx = namespace.ContextWithNamespace(ctx, ns)
				}
			}
		}

	// Prevent any metrics requests to be forwarded from a standby node.
	// Instead, we return an error since we cannot be sure if we have an
	// active token store to validate the provided token.
	case strings.HasPrefix(req.Path, "sys/metrics"):
		if c.standby {
			return nil, ErrCannotForwardLocalOnly
		}
	}

	var auth *logical.Auth
	if c.isLoginRequest(ctx, req) {
		resp, auth, err = c.handleLoginRequest(ctx, req)
	} else {
		resp, auth, err = c.handleRequest(ctx, req)
	}

	if err == nil && c.requestResponseCallback != nil {
		c.requestResponseCallback(c.router.MatchingBackend(ctx, req.Path), req, resp)
	}

	// If we saved the token in the request, we should return it in the response
	// data.
	if resp != nil && resp.Data != nil {
		if _, ok := resp.Data["error"]; !ok {
			if requestBodyToken != "" {
				resp.Data["id"] = requestBodyToken
			} else if returnRequestAuthToken && req.InboundSSCToken != "" {
				resp.Data["id"] = req.InboundSSCToken
			}
		}
	}
	if resp != nil && resp.Auth != nil && requestBodyToken != "" {
		// if a client token has already been set and the request body token's internal token
		// is equal to that value, then we can return the original request body token
		tok, _ := c.DecodeSSCToken(requestBodyToken)
		if resp.Auth.ClientToken == tok {
			resp.Auth.ClientToken = requestBodyToken
		}
	}

	// Ensure we don't leak internal data
	if resp != nil {
		if resp.Secret != nil {
			resp.Secret.InternalData = nil
		}
		if resp.Auth != nil {
			resp.Auth.InternalData = nil
		}
	}

	// We are wrapping if there is anything to wrap (not a nil response) and a
	// TTL was specified for the token. Errors on a call should be returned to
	// the caller, so wrapping is turned off if an error is hit and the error
	// is logged to the audit log.
	wrapping := resp != nil &&
		err == nil &&
		!resp.IsError() &&
		resp.WrapInfo != nil &&
		resp.WrapInfo.TTL != 0 &&
		resp.WrapInfo.Token == ""

	if wrapping {
		cubbyResp, cubbyErr := c.wrapInCubbyhole(ctx, req, resp, auth)
		// If not successful, returns either an error response from the
		// cubbyhole backend or an error; if either is set, set resp and err to
		// those and continue so that that's what we audit log. Otherwise
		// finish the wrapping and audit log that.
		if cubbyResp != nil || cubbyErr != nil {
			resp = cubbyResp
			err = cubbyErr
		} else {
			wrappingResp := &logical.Response{
				WrapInfo: resp.WrapInfo,
				Warnings: resp.Warnings,
			}
			resp = wrappingResp
		}
	}

	auditResp := resp
	// When unwrapping we want to log the actual response that will be written
	// out. We still want to return the raw value to avoid automatic updating
	// to any of it.
	if req.Path == "sys/wrapping/unwrap" &&
		resp != nil &&
		resp.Data != nil &&
		resp.Data[logical.HTTPRawBody] != nil {

		// Decode the JSON
		if resp.Data[logical.HTTPRawBodyAlreadyJSONDecoded] != nil {
			delete(resp.Data, logical.HTTPRawBodyAlreadyJSONDecoded)
		} else {
			httpResp := &logical.HTTPResponse{}
			err := jsonutil.DecodeJSON(resp.Data[logical.HTTPRawBody].([]byte), httpResp)
			if err != nil {
				c.logger.Error("failed to unmarshal wrapped HTTP response for audit logging", "error", err)
				return nil, ErrInternalError
			}

			auditResp = logical.HTTPResponseToLogicalResponse(httpResp)
		}
	}

	var nonHMACReqDataKeys []string
	var nonHMACRespDataKeys []string
	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Get and set ignored HMAC'd value. Reset those back to empty afterwards.
		if rawVals, ok := entry.synthesizedConfigCache.Load("audit_non_hmac_request_keys"); ok {
			nonHMACReqDataKeys = rawVals.([]string)
		}

		// Get and set ignored HMAC'd value. Reset those back to empty afterwards.
		if auditResp != nil {
			if rawVals, ok := entry.synthesizedConfigCache.Load("audit_non_hmac_response_keys"); ok {
				nonHMACRespDataKeys = rawVals.([]string)
			}
		}
	}

	// Create an audit trail of the response
	logInput := &logical.LogInput{
		Auth:                auth,
		Request:             req,
		Response:            auditResp,
		OuterErr:            err,
		NonHMACReqDataKeys:  nonHMACReqDataKeys,
		NonHMACRespDataKeys: nonHMACRespDataKeys,
	}
	if auditErr := c.auditBroker.LogResponse(ctx, logInput, c.auditedHeaders); auditErr != nil {
		c.logger.Error("failed to audit response", "request_path", req.Path, "error", auditErr)
		return nil, ErrInternalError
	}

	return resp, err
}

func (c *Core) doRouting(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	// If we're replicating and we get a read-only error from a backend, need to forward to primary
	return c.router.Route(ctx, req)
}

func (c *Core) isLoginRequest(ctx context.Context, req *logical.Request) bool {
	return c.router.LoginPath(ctx, req.Path)
}

func (c *Core) handleRequest(ctx context.Context, req *logical.Request) (retResp *logical.Response, retAuth *logical.Auth, retErr error) {
	defer metrics.MeasureSince([]string{"core", "handle_request"}, time.Now())

	var nonHMACReqDataKeys []string
	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Set here so the audit log has it even if authorization fails
		req.MountType = entry.Type
		req.SetMountRunningSha256(entry.RunningSha256)
		req.SetMountRunningVersion(entry.RunningVersion)
		req.SetMountIsExternalPlugin(entry.IsExternalPlugin())
		req.SetMountClass(entry.MountClass())

		// Get and set ignored HMAC'd value.
		if rawVals, ok := entry.synthesizedConfigCache.Load("audit_non_hmac_request_keys"); ok {
			nonHMACReqDataKeys = rawVals.([]string)
		}
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		c.logger.Error("failed to get namespace from context", "error", err)
		retErr = multierror.Append(retErr, ErrInternalError)
		return retResp, retAuth, retErr
	}

	// Validate the token
	auth, acl, te, entity, ctErr := c.CheckToken(ctx, req, false)
	if ctErr == logical.ErrRelativePath {
		return logical.ErrorResponse(ctErr.Error()), nil, ctErr
	}
	if ctErr == logical.ErrPerfStandbyPleaseForward {
		return nil, nil, ctErr
	}

	// Updating in-flight request data with client/entity ID
	inFlightReqID, ok := ctx.Value(logical.CtxKeyInFlightRequestID{}).(string)
	if ok && req.ClientID != "" {
		c.UpdateInFlightReqData(inFlightReqID, req.ClientID)
	}

	// We run this logic first because we want to decrement the use count even
	// in the case of an error (assuming we can successfully look up; if we
	// need to forward, we exit before now)
	if te != nil {
		// Attempt to use the token (decrement NumUses)
		var err error
		te, err = c.tokenStore.UseToken(ctx, te)
		if err != nil {
			c.logger.Error("failed to use token", "error", err)
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, nil, retErr
		}
		if te == nil {
			// Token has been revoked by this point
			retErr = multierror.Append(retErr, logical.ErrPermissionDenied)
			return nil, nil, retErr
		}
		if te.NumUses == tokenRevocationPending {
			// We defer a revocation until after logic has run, since this is a
			// valid request (this is the token's final use). We pass the ID in
			// directly just to be safe in case something else modifies te later.
			defer func(id string) {
				nsActiveCtx := namespace.ContextWithNamespace(c.activeContext, ns)
				leaseID, err := c.expiration.CreateOrFetchRevocationLeaseByToken(nsActiveCtx, te)
				if err == nil {
					err = c.expiration.LazyRevoke(ctx, leaseID)
				}
				if err != nil {
					c.logger.Error("failed to revoke token", "error", err)
					retResp = nil
					retAuth = nil
					retErr = multierror.Append(retErr, ErrInternalError)
				}
				if retResp != nil && retResp.Secret != nil &&
					// Some backends return a TTL even without a Lease ID
					retResp.Secret.LeaseID != "" {
					retResp = logical.ErrorResponse("Secret cannot be returned; token had one use left, so leased credentials were immediately revoked.")
					return
				}
			}(te.ID)
		}
	}

	if ctErr != nil {
		// If it is an internal error we return that, otherwise we
		// return invalid request so that the status codes can be correct
		switch {
		case ctErr == ErrInternalError,
			errwrap.Contains(ctErr, ErrInternalError.Error()),
			ctErr == logical.ErrPermissionDenied,
			errwrap.Contains(ctErr, logical.ErrPermissionDenied.Error()):
			switch ctErr.(type) {
			case *multierror.Error:
				retErr = ctErr
			default:
				retErr = multierror.Append(retErr, ctErr)
			}
		default:
			retErr = multierror.Append(retErr, logical.ErrInvalidRequest)
		}

		logInput := &logical.LogInput{
			Auth:               auth,
			Request:            req,
			OuterErr:           ctErr,
			NonHMACReqDataKeys: nonHMACReqDataKeys,
		}
		if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
			c.logger.Error("failed to audit request", "path", req.Path, "error", err)
		}

		if errwrap.Contains(retErr, ErrInternalError.Error()) {
			return nil, auth, retErr
		}
		return logical.ErrorResponse(ctErr.Error()), auth, retErr
	}

	// Attach the display name
	req.DisplayName = auth.DisplayName

	// Create an audit trail of the request
	logInput := &logical.LogInput{
		Auth:               auth,
		Request:            req,
		NonHMACReqDataKeys: nonHMACReqDataKeys,
	}
	if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
		c.logger.Error("failed to audit request", "path", req.Path, "error", err)
		retErr = multierror.Append(retErr, ErrInternalError)
		return nil, auth, retErr
	}

	// Route the request
	resp, routeErr := c.doRouting(ctx, req)
	if resp != nil {

		// If wrapping is used, use the shortest between the request and response
		var wrapTTL time.Duration
		var wrapFormat, creationPath string
		var sealWrap bool

		// Ensure no wrap info information is set other than, possibly, the TTL
		if resp.WrapInfo != nil {
			if resp.WrapInfo.TTL > 0 {
				wrapTTL = resp.WrapInfo.TTL
			}
			wrapFormat = resp.WrapInfo.Format
			creationPath = resp.WrapInfo.CreationPath
			sealWrap = resp.WrapInfo.SealWrap
			resp.WrapInfo = nil
		}

		if req.WrapInfo != nil {
			if req.WrapInfo.TTL > 0 {
				switch {
				case wrapTTL == 0:
					wrapTTL = req.WrapInfo.TTL
				case req.WrapInfo.TTL < wrapTTL:
					wrapTTL = req.WrapInfo.TTL
				}
			}
			// If the wrap format hasn't been set by the response, set it to
			// the request format
			if req.WrapInfo.Format != "" && wrapFormat == "" {
				wrapFormat = req.WrapInfo.Format
			}
		}

		if wrapTTL > 0 {
			resp.WrapInfo = &wrapping.ResponseWrapInfo{
				TTL:          wrapTTL,
				Format:       wrapFormat,
				CreationPath: creationPath,
				SealWrap:     sealWrap,
			}
		}

		// Ensure compliance with List operation filtering.
		if err := c.filterListResponse(ctx, req, false, auth, acl, te, entity, resp); err != nil {
			return nil, nil, err
		}
	}

	// If there is a secret, we must register it with the expiration manager.
	// We exclude renewal of a lease, since it does not need to be re-registered
	if resp != nil && resp.Secret != nil && !strings.HasPrefix(req.Path, "sys/renew") &&
		!strings.HasPrefix(req.Path, "sys/leases/renew") {
		// KV mounts should return the TTL but not register
		// for a lease as this provides a massive slowdown
		registerLease := true

		matchingMountEntry := c.router.MatchingMountEntry(ctx, req.Path)
		if matchingMountEntry == nil {
			c.logger.Error("unable to retrieve kv mount entry from router")
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, auth, retErr
		}

		switch matchingMountEntry.Type {
		case "kv", "generic":
			// If we are kv type, first see if we are an older passthrough
			// backend, and otherwise check the mount entry options.
			matchingBackend := c.router.MatchingBackend(ctx, req.Path)
			if matchingBackend == nil {
				c.logger.Error("unable to retrieve kv backend from router")
				retErr = multierror.Append(retErr, ErrInternalError)
				return nil, auth, retErr
			}

			if ptbe, ok := matchingBackend.(*PassthroughBackend); ok {
				if !ptbe.GeneratesLeases() {
					registerLease = false
					resp.Secret.Renewable = false
				}
			} else if matchingMountEntry.Options == nil || matchingMountEntry.Options["leased_passthrough"] != "true" {
				registerLease = false
				resp.Secret.Renewable = false
			}

		case "plugin":
			// If we are a plugin type and the plugin name is "kv" check the
			// mount entry options.
			if matchingMountEntry.Config.PluginName == "kv" && (matchingMountEntry.Options == nil || matchingMountEntry.Options["leased_passthrough"] != "true") {
				registerLease = false
				resp.Secret.Renewable = false
			}
		}

		if registerLease {
			if req.HasInlineAuth {
				// When we've performed inline authentication and see a lease created,
				// we must revoke this lease even though it isn't yet persisted. Throw
				// an error.
				revokeLease, err := c.router.Route(ctx, logical.RevokeRequest(req.Path, resp.Secret, resp.Data))
				if err != nil {
					return nil, nil, fmt.Errorf("failed to revoke ephemeral lease generated during inline authentication: %w", err)
				}
				if revokeLease != nil && revokeLease.IsError() {
					return nil, nil, fmt.Errorf("failed to revoke ephemeral lease generated during inline authentication: %w", revokeLease.Error())
				}

				return nil, nil, errutil.UserError{Err: "requests with inline authentication cannot generate leases"}
			}

			sysView := c.router.MatchingSystemView(ctx, req.Path)
			if sysView == nil {
				c.logger.Error("unable to look up sys view for login path", "request_path", req.Path)
				return nil, nil, ErrInternalError
			}

			ttl, warnings, err := framework.CalculateTTL(sysView, 0, resp.Secret.TTL, 0, resp.Secret.MaxTTL, 0, time.Time{})
			if err != nil {
				return nil, nil, err
			}
			for _, warning := range warnings {
				resp.AddWarning(warning)
			}
			resp.Secret.TTL = ttl

			leaseID, err := c.expiration.Register(ctx, req, resp, "")
			if err != nil {
				c.logger.Error("failed to register lease", "request_path", req.Path, "error", err)
				retErr = multierror.Append(retErr, ErrInternalError)
				return nil, auth, retErr
			}
			resp.Secret.LeaseID = leaseID

			// Count the lease creation
			ttl_label := metricsutil.TTLBucket(resp.Secret.TTL)
			mountPointWithoutNs := ns.TrimmedPath(req.MountPoint)
			c.MetricSink().IncrCounterWithLabels(
				[]string{"secret", "lease", "creation"},
				1,
				[]metrics.Label{
					metricsutil.NamespaceLabel(ns),
					{Name: "secret_engine", Value: req.MountType},
					{Name: "mount_point", Value: mountPointWithoutNs},
					{Name: "creation_ttl", Value: ttl_label},
				},
			)
		}
	}

	// Only the token store is allowed to return an auth block, for any
	// other request this is an internal error.
	if resp != nil && resp.Auth != nil {
		if !strings.HasPrefix(req.Path, "auth/token/") {
			c.logger.Error("unexpected Auth response for non-token backend", "request_path", req.Path)
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, auth, retErr
		}

		// Fetch the namespace to which the token belongs
		tokenNS, err := c.NamespaceByID(ctx, te.NamespaceID)
		if err != nil {
			c.logger.Error("failed to fetch token's namespace", "error", err)
			retErr = multierror.Append(retErr, err)
			return nil, auth, retErr
		}
		if tokenNS == nil {
			c.logger.Error(namespace.ErrNoNamespace.Error())
			retErr = multierror.Append(retErr, namespace.ErrNoNamespace)
			return nil, auth, retErr
		}

		_, identityPolicies, err := c.fetchEntityAndDerivedPolicies(ctx, tokenNS, resp.Auth.EntityID, false)
		if err != nil {
			// Best-effort clean up on error, so we log the cleanup error as a
			// warning but still return as internal error.
			if err := c.tokenStore.revokeOrphan(ctx, resp.Auth.ClientToken); err != nil {
				c.logger.Warn("failed to clean up token lease from entity and policy lookup failure", "request_path", req.Path, "error", err)
			}
			return nil, nil, ErrInternalError
		}

		// We skip expiration manager registration for token renewal since it
		// does not need to be re-registered
		if strings.HasPrefix(req.Path, "auth/token/renew") {
			// We build the "policies" list to be returned by starting with
			// token policies, and add identity policies right after this
			// conditional
			tok, _ := c.DecodeSSCToken(req.InboundSSCToken)
			if resp.Auth.ClientToken == tok {
				resp.Auth.ClientToken = req.InboundSSCToken
			}
			resp.Auth.Policies = policyutil.SanitizePolicies(resp.Auth.TokenPolicies, policyutil.DoNotAddDefaultPolicy)
		} else {
			resp.Auth.TokenPolicies = policyutil.SanitizePolicies(resp.Auth.Policies, policyutil.DoNotAddDefaultPolicy)

			switch resp.Auth.TokenType {
			case logical.TokenTypeBatch:
			case logical.TokenTypeService:
				registeredTokenEntry := &logical.TokenEntry{
					TTL:         auth.TTL,
					Policies:    auth.TokenPolicies,
					Path:        resp.Auth.CreationPath,
					NamespaceID: ns.ID,
				}

				// Only logins apply to role based quotas, so we can omit the role here, as we are not logging in.
				if err := c.expiration.RegisterAuth(ctx, registeredTokenEntry, resp.Auth, "", true /* persist */); err != nil {
					// Best-effort clean up on error, so we log the cleanup error as
					// a warning but still return as internal error.
					if err := c.tokenStore.revokeOrphan(ctx, resp.Auth.ClientToken); err != nil {
						c.logger.Warn("failed to clean up token lease during auth/token/ request", "request_path", req.Path, "error", err)
					}
					c.logger.Error("failed to register token lease during auth/token/ request", "request_path", req.Path, "error", err)
					retErr = multierror.Append(retErr, ErrInternalError)
					return nil, auth, retErr
				}
				if registeredTokenEntry.ExternalID != "" {
					resp.Auth.ClientToken = registeredTokenEntry.ExternalID
				}
			}
		}

		// We do these later since it's not meaningful for backends/expmgr to
		// have what is purely a snapshot of current identity policies, and
		// plugins can be confused if they are checking contents of
		// Auth.Policies instead of Auth.TokenPolicies
		resp.Auth.Policies = policyutil.SanitizePolicies(append(resp.Auth.Policies, identityPolicies[te.NamespaceID]...), policyutil.DoNotAddDefaultPolicy)
		resp.Auth.IdentityPolicies = policyutil.SanitizePolicies(identityPolicies[te.NamespaceID], policyutil.DoNotAddDefaultPolicy)
		delete(identityPolicies, te.NamespaceID)
		resp.Auth.ExternalNamespacePolicies = identityPolicies
	}

	if resp != nil &&
		req.Path == "cubbyhole/response" &&
		len(te.Policies) == 1 &&
		te.Policies[0] == responseWrappingPolicyName {
		resp.AddWarning("Reading from 'cubbyhole/response' is deprecated. Please use sys/wrapping/unwrap to unwrap responses, as it provides additional security checks and other benefits.")
	}

	// Return the response and error
	if routeErr != nil {
		retErr = multierror.Append(retErr, routeErr)
	}

	return resp, auth, retErr
}

// handleLoginRequest is used to handle a login request, which is an
// unauthenticated request to the backend.
func (c *Core) handleLoginRequest(ctx context.Context, req *logical.Request) (retResp *logical.Response, retAuth *logical.Auth, retErr error) {
	defer metrics.MeasureSince([]string{"core", "handle_login_request"}, time.Now())

	req.Unauthenticated = true

	var nonHMACReqDataKeys []string
	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Set here so the audit log has it even if authorization fails
		req.MountType = entry.Type
		req.SetMountRunningSha256(entry.RunningSha256)
		req.SetMountRunningVersion(entry.RunningVersion)
		req.SetMountIsExternalPlugin(entry.IsExternalPlugin())
		req.SetMountClass(entry.MountClass())

		// Get and set ignored HMAC'd value.
		if rawVals, ok := entry.synthesizedConfigCache.Load("audit_non_hmac_request_keys"); ok {
			nonHMACReqDataKeys = rawVals.([]string)
		}
	}

	// Do an unauth check. This will cause EGP policies to be checked
	var auth *logical.Auth
	var acl *ACL
	var te *logical.TokenEntry
	var entity *identity.Entity
	var ctErr error
	auth, acl, te, entity, ctErr = c.CheckToken(ctx, req, true)
	if ctErr == logical.ErrPerfStandbyPleaseForward {
		return nil, nil, ctErr
	}

	// Updating in-flight request data with client/entity ID
	inFlightReqID, ok := ctx.Value(logical.CtxKeyInFlightRequestID{}).(string)
	if ok && req.ClientID != "" {
		c.UpdateInFlightReqData(inFlightReqID, req.ClientID)
	}

	if ctErr != nil {
		// If it is an internal error we return that, otherwise we
		// return invalid request so that the status codes can be correct
		var errType error
		switch ctErr {
		case ErrInternalError, logical.ErrPermissionDenied:
			errType = ctErr
		default:
			errType = logical.ErrInvalidRequest
		}

		logInput := &logical.LogInput{
			Auth:               auth,
			Request:            req,
			OuterErr:           ctErr,
			NonHMACReqDataKeys: nonHMACReqDataKeys,
		}
		if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
			c.logger.Error("failed to audit request", "path", req.Path, "error", err)
			return nil, nil, ErrInternalError
		}

		if errType != nil {
			retErr = multierror.Append(retErr, errType)
		}
		if ctErr == ErrInternalError {
			return nil, auth, retErr
		}
		return logical.ErrorResponse(ctErr.Error()), auth, retErr
	}

	switch req.Path {
	default:
		// Create an audit trail of the request. Attach auth if it was returned,
		// e.g. if a token was provided.
		logInput := &logical.LogInput{
			Auth:               auth,
			Request:            req,
			NonHMACReqDataKeys: nonHMACReqDataKeys,
		}
		if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
			c.logger.Error("failed to audit request", "path", req.Path, "error", err)
			return nil, nil, ErrInternalError
		}
	}

	// The token store uses authentication even when creating a new token,
	// so it's handled in handleRequest. It should not be reached here.
	if strings.HasPrefix(req.Path, "auth/token/") {
		c.logger.Error("unexpected login request for token backend", "request_path", req.Path)
		return nil, nil, ErrInternalError
	}

	// check if user lockout feature is disabled
	isUserLockoutDisabled, err := c.isUserLockoutDisabled(entry)
	if err != nil {
		return nil, nil, err
	}

	// if user lockout feature is not disabled, check if the user is locked
	var userLockoutInfo *FailedLoginUser
	if !isUserLockoutDisabled {
		lockoutInfo, isloginUserLocked, err := c.isUserLocked(ctx, entry, req)
		if err != nil {
			return nil, nil, err
		}
		if isloginUserLocked {
			return nil, nil, logical.ErrPermissionDenied
		}
		userLockoutInfo = lockoutInfo
	}

	// Route the request
	resp, routeErr := c.doRouting(ctx, req)

	// if routeErr has invalid credentials error, update the userFailedLoginMap
	if routeErr != nil && routeErr == logical.ErrInvalidCredentials {
		if !isUserLockoutDisabled {
			err := c.failedUserLoginProcess(ctx, entry, req, userLockoutInfo)
			if err != nil {
				return nil, nil, err
			}
		}
		return resp, nil, routeErr
	}

	if resp != nil {
		// If wrapping is used, use the shortest between the request and response
		var wrapTTL time.Duration
		var wrapFormat, creationPath string
		var sealWrap bool

		// Ensure no wrap info information is set other than, possibly, the TTL
		if resp.WrapInfo != nil {
			if resp.WrapInfo.TTL > 0 {
				wrapTTL = resp.WrapInfo.TTL
			}
			wrapFormat = resp.WrapInfo.Format
			creationPath = resp.WrapInfo.CreationPath
			sealWrap = resp.WrapInfo.SealWrap
			resp.WrapInfo = nil
		}

		if req.WrapInfo != nil {
			if req.WrapInfo.TTL > 0 {
				switch {
				case wrapTTL == 0:
					wrapTTL = req.WrapInfo.TTL
				case req.WrapInfo.TTL < wrapTTL:
					wrapTTL = req.WrapInfo.TTL
				}
			}
			if req.WrapInfo.Format != "" && wrapFormat == "" {
				wrapFormat = req.WrapInfo.Format
			}
		}

		if wrapTTL > 0 {
			resp.WrapInfo = &wrapping.ResponseWrapInfo{
				TTL:          wrapTTL,
				Format:       wrapFormat,
				CreationPath: creationPath,
				SealWrap:     sealWrap,
			}
		}

		// Ensure compliance with List operation filtering.
		if err := c.filterListResponse(ctx, req, true, auth, acl, te, entity, resp); err != nil {
			return nil, nil, err
		}
	}

	// A login request should never return a secret!
	if resp != nil && resp.Secret != nil {
		c.logger.Error("unexpected Secret response for login path", "request_path", req.Path)
		return nil, nil, ErrInternalError
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		c.logger.Error("failed to get namespace from context", "error", err)
		retErr = multierror.Append(retErr, ErrInternalError)
		return retResp, retAuth, retErr
	}
	// If the response generated an authentication, then generate the token
	if resp != nil && resp.Auth != nil && req.Path != "sys/mfa/validate" {
		// Check for request role in context to role based quotas
		var role string
		reqRole := ctx.Value(logical.CtxKeyRequestRole{})
		if reqRole != nil {
			role = reqRole.(string)
		}

		var entity *identity.Entity
		auth = resp.Auth

		mEntry := c.router.MatchingMountEntry(ctx, req.Path)

		if auth.Alias != nil &&
			mEntry != nil &&
			c.identityStore != nil {

			if mEntry.Local && api.ReadBaoVariable(EnvVaultDisableLocalAuthMountEntities) != "" {
				goto CREATE_TOKEN
			}

			// Overwrite the mount type and mount path in the alias
			// information
			auth.Alias.MountType = req.MountType
			auth.Alias.MountAccessor = req.MountAccessor
			auth.Alias.Local = mEntry.Local

			if auth.Alias.Name == "" {
				return nil, nil, errors.New("missing name in alias")
			}

			var err error
			// Fetch the entity for the alias, or create an entity if one
			// doesn't exist.
			entity, entityCreated, err := c.identityStore.CreateOrFetchEntity(ctx, auth.Alias)
			if err != nil {
				return nil, nil, err
			}
			if entity == nil {
				return nil, nil, errors.New("failed to create an entity for the authenticated alias")
			}

			if entity.Disabled {
				return nil, nil, logical.ErrPermissionDenied
			}

			auth.EntityID = entity.ID
			auth.EntityCreated = entityCreated
			validAliases, err := c.identityStore.refreshExternalGroupMembershipsByEntityID(ctx, auth.EntityID, auth.GroupAliases, req.MountAccessor)
			if err != nil {
				return nil, nil, err
			}
			auth.GroupAliases = validAliases
		}

	CREATE_TOKEN:
		// Determine the source of the login
		source := c.router.MatchingMount(ctx, req.Path)

		// Login MFA
		entity, _, err := c.fetchEntityAndDerivedPolicies(ctx, ns, auth.EntityID, true)
		if err != nil {
			return nil, nil, ErrInternalError
		}
		// finding the MFAEnforcementConfig that matches the ns and either of
		// entityID, MountAccessor, GroupID, or Auth type.
		matchedMfaEnforcementList, err := c.buildMFAEnforcementConfigList(ctx, entity, req.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find MFAEnforcement configuration, error: %v", err)
		}

		// (for the context, a response warning above says: "primary cluster
		// doesn't yet issue entities for local auth mounts; falling back
		// to not issuing entities for local auth mounts")
		// based on the above, if the entity is nil, check if MFAEnforcementConfig
		// is configured or not. If not, continue as usual, but if there
		// is something, then report an error indicating that the user is not
		// allowed to login because there is no entity associated with it.
		// This is because an entity is needed to enforce MFA.
		if entity == nil && len(matchedMfaEnforcementList) > 0 {
			// this logic means that an MFAEnforcementConfig was configured with
			// only mount type or mount accessor
			return nil, nil, logical.ErrPermissionDenied
		}

		// The resp.Auth has been populated with the information that is required for MFA validation
		// This is why, the MFA check is placed at this point. The resp.Auth is going to be fully cached
		// in memory so that it would be used to return to the user upon MFA validation is completed.
		if entity != nil {
			if len(matchedMfaEnforcementList) == 0 && len(req.MFACreds) > 0 {
				resp.AddWarning("Found MFA header but failed to find MFA Enforcement Config")
			}

			// If X-Vault-MFA header is supplied to the login request,
			// run single-phase login MFA check, else run two-phase login MFA check
			if len(matchedMfaEnforcementList) > 0 && len(req.MFACreds) > 0 {
				for _, eConfig := range matchedMfaEnforcementList {
					err = c.validateLoginMFA(ctx, eConfig, entity, req.Connection.RemoteAddr, req.MFACreds)
					if err != nil {
						return nil, nil, logical.ErrPermissionDenied
					}
				}
			} else if len(matchedMfaEnforcementList) > 0 && len(req.MFACreds) == 0 {
				if req.IsInlineAuth {
					return nil, nil, fmt.Errorf("unable to perform inline authentication with login MFA; use the X-Vault-MFA header to specify MFA information on the inline auth request")
				}

				mfaRequestID, err := uuid.GenerateUUID()
				if err != nil {
					return nil, nil, err
				}
				// sending back the MFARequirement config
				mfaRequirement := &logical.MFARequirement{
					MFARequestID:   mfaRequestID,
					MFAConstraints: make(map[string]*logical.MFAConstraintAny),
				}
				for _, eConfig := range matchedMfaEnforcementList {
					mfaAny, err := c.buildMfaEnforcementResponse(eConfig)
					if err != nil {
						return nil, nil, err
					}
					mfaRequirement.MFAConstraints[eConfig.Name] = mfaAny
				}

				// for two phased MFA enforcement, we should not return the regular auth
				// response. This flag is indicate to store the auth response for later
				// and return MFARequirement only
				respAuth := &MFACachedAuthResponse{
					CachedAuth:            resp.Auth,
					CachedUserLockout:     userLockoutInfo,
					RequestPath:           req.Path,
					RequestNSID:           ns.ID,
					RequestNSPath:         ns.Path,
					RequestConnRemoteAddr: req.Connection.RemoteAddr, // this is needed for the DUO method
					TimeOfStorage:         time.Now(),
					RequestID:             mfaRequestID,
				}
				if err := c.SaveMFAResponseAuth(respAuth); err != nil {
					return nil, nil, err
				}

				auth = nil
				resp.Auth = &logical.Auth{
					MFARequirement: mfaRequirement,
				}
				resp.AddWarning("A login request was issued that is subject to MFA validation. Please make sure to validate the login by sending another request to mfa/validate endpoint.")
				// going to return early before generating the token
				// the user receives the mfaRequirement, and need to use the
				// login MFA validate endpoint to get the token
				return resp, auth, nil
			}
		}

		// Attach the display name, might be used by audit backends
		req.DisplayName = auth.DisplayName

		requiresLease := resp.Auth.TokenType != logical.TokenTypeBatch

		// If role was not already determined by http.rateLimitQuotaWrapping
		// and a lease will be generated, calculate a role for the leaseEntry.
		// We can skip this step if there are no pre-existing role-based quotas
		// for this mount and Vault is configured to skip lease role-based lease counting
		// until after they're created. This effectively zeroes out the lease count
		// for new role-based quotas upon creation, rather than counting old leases toward
		// the total.
		if reqRole == nil && requiresLease && !c.impreciseLeaseRoleTracking {
			role = c.DetermineRoleFromLoginRequest(ctx, req.MountPoint, req.Data)
		}

		_, respTokenCreate, errCreateToken := c.LoginCreateToken(ctx, ns, req.Path, source, role, resp, req.IsInlineAuth, userLockoutInfo)
		if errCreateToken != nil {
			return respTokenCreate, nil, errCreateToken
		}
		resp = respTokenCreate
	}

	// Successful login, remove any entry from userFailedLoginInfo map
	// if it exists. This is done for batch tokens (for oss & ent)
	// For service tokens on oss it is taken care by core RegisterAuth function.
	// For service tokens on ent it is taken care by registerAuth RPC calls.
	// This update is done as part of registerAuth of RPC calls from standby
	// to active node. This is added there to reduce RPC calls
	if !isUserLockoutDisabled && (auth.TokenType == logical.TokenTypeBatch) && userLockoutInfo != nil {
		// We don't need to try to delete the lockedUsers storage entry, since we're
		// processing a login request. If a login attempt is allowed, it means the user is
		// unlocked and we only add storage entry when the user gets locked.
		err = c.LocalUpdateUserFailedLoginInfo(ctx, *userLockoutInfo, nil, true)
		if err != nil {
			return nil, nil, err
		}
	}

	// if we were already going to return some error from this login, do that.
	// if not, we will then check if the API is locked for the requesting
	// namespace, to avoid leaking locked namespaces to unauthenticated clients.
	if resp != nil && resp.Data != nil {
		if _, ok := resp.Data["error"]; ok {
			return resp, auth, routeErr
		}
	}
	if routeErr != nil {
		return resp, auth, routeErr
	}

	return resp, auth, routeErr
}

// LoginCreateToken creates a token as a result of a login request.
// If MFA is enforced, mfa/validate endpoint calls this functions
// after successful MFA validation to generate the token.
func (c *Core) LoginCreateToken(ctx context.Context, ns *namespace.Namespace, reqPath, mountPoint, role string, resp *logical.Response, isInlineAuth bool, userLockoutInfo *FailedLoginUser) (bool, *logical.Response, error) {
	auth := resp.Auth
	source := strings.TrimPrefix(mountPoint, credentialRoutePrefix)
	source = strings.ReplaceAll(source, "/", "-")

	// Prepend the source to the display name
	auth.DisplayName = strings.TrimSuffix(source+auth.DisplayName, "-")

	// Determine mount type
	mountEntry := c.router.MatchingMountEntry(ctx, reqPath)
	if mountEntry == nil {
		return false, nil, errors.New("failed to find a matching mount")
	}

	sysView := c.router.MatchingSystemView(ctx, reqPath)
	if sysView == nil {
		c.logger.Error("unable to look up sys view for login path", "request_path", reqPath)
		return false, nil, ErrInternalError
	}

	tokenTTL, warnings, err := framework.CalculateTTL(sysView, 0, auth.TTL, auth.Period, auth.MaxTTL, auth.ExplicitMaxTTL, time.Time{})
	if err != nil {
		return false, nil, err
	}
	for _, warning := range warnings {
		resp.AddWarning(warning)
	}

	_, identityPolicies, err := c.fetchEntityAndDerivedPolicies(ctx, ns, auth.EntityID, false)
	if err != nil {
		return false, nil, ErrInternalError
	}

	auth.TokenPolicies = policyutil.SanitizePolicies(auth.Policies, !auth.NoDefaultPolicy)
	allPolicies := policyutil.SanitizePolicies(append(auth.TokenPolicies, identityPolicies[ns.ID]...), policyutil.DoNotAddDefaultPolicy)

	// Prevent internal policies from being assigned to tokens. We check
	// this on auth.Policies including derived ones from Identity before
	// actually making the token.
	for _, policy := range allPolicies {
		if policy == "root" {
			return false, logical.ErrorResponse("auth methods cannot create root tokens"), logical.ErrInvalidRequest
		}
		if slices.Contains(nonAssignablePolicies, policy) {
			return false, logical.ErrorResponse("cannot assign policy %q", policy), logical.ErrInvalidRequest
		}
	}

	leaseGenerated := false
	te, err := c.RegisterAuth(ctx, tokenTTL, reqPath, auth, role, !isInlineAuth, userLockoutInfo)
	switch err {
	case nil:
		if auth.TokenType != logical.TokenTypeBatch {
			leaseGenerated = true
		}
	case ErrInternalError:
		return false, nil, err
	default:
		return false, logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	auth.IdentityPolicies = policyutil.SanitizePolicies(identityPolicies[ns.ID], policyutil.DoNotAddDefaultPolicy)
	delete(identityPolicies, ns.ID)
	auth.ExternalNamespacePolicies = identityPolicies
	auth.Policies = allPolicies

	// Count the successful token creation
	ttl_label := metricsutil.TTLBucket(tokenTTL)
	// Do not include namespace path in mount point; already present as separate label.
	mountPointWithoutNs := ns.TrimmedPath(mountPoint)
	c.metricSink.IncrCounterWithLabels(
		[]string{"token", "creation"},
		1,
		[]metrics.Label{
			metricsutil.NamespaceLabel(ns),
			{Name: "auth_method", Value: mountEntry.Type},
			{Name: "mount_point", Value: mountPointWithoutNs},
			{Name: "creation_ttl", Value: ttl_label},
			{Name: "token_type", Value: auth.TokenType.String()},
		},
	)

	if isInlineAuth {
		resp.InlineAuthTokenEntry = te
	}

	return leaseGenerated, resp, nil
}

// failedUserLoginProcess updates the userFailedLoginMap with login count and  last failed
// login time for users with failed login attempt
// If the user gets locked for current login attempt, it updates the storage entry too
func (c *Core) failedUserLoginProcess(ctx context.Context, mountEntry *MountEntry, req *logical.Request, userLockoutInfo *FailedLoginUser) error {
	// get the user lockout configuration for the user
	userLockoutConfiguration := c.getUserLockoutConfiguration(mountEntry)

	// get entry from userFailedLoginInfo map for the key
	userFailedLoginInfo := c.LocalGetUserFailedLoginInfo(ctx, *userLockoutInfo)

	// update the last failed login time with current time
	failedLoginInfo := FailedLoginInfo{
		lastFailedLoginTime: int(time.Now().Unix()),
	}

	// set the failed login count value for the entry in userFailedLoginInfo map
	switch userFailedLoginInfo {
	case nil: // entry does not exist in userfailedLoginMap
		failedLoginInfo.count = 1
	default:
		failedLoginInfo.count = userFailedLoginInfo.count + 1

		// if counter reset, set the count value to 1 as this gets counted as new entry
		lastFailedLoginTime := time.Unix(int64(userFailedLoginInfo.lastFailedLoginTime), 0)
		counterResetDuration := userLockoutConfiguration.LockoutCounterReset
		if time.Now().After(lastFailedLoginTime.Add(counterResetDuration)) {
			failedLoginInfo.count = 1
		}
	}

	// update the userFailedLoginInfo map (and/or storage) with the updated/new entry
	err := c.LocalUpdateUserFailedLoginInfo(ctx, *userLockoutInfo, &failedLoginInfo, false)
	if err != nil {
		return err
	}

	return nil
}

// getLoginUserInfoKey gets failedUserLoginInfo map key for login user
func (c *Core) getLoginUserInfoKey(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (FailedLoginUser, error) {
	userInfo := FailedLoginUser{}
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	if err != nil {
		return userInfo, err
	}
	if aliasName == "" {
		return userInfo, errors.New("failed to determine alias name from login request")
	}

	userInfo.aliasName = aliasName
	userInfo.mountAccessor = mountEntry.Accessor
	return userInfo, nil
}

// isUserLockoutDisabled checks if user lockout feature to prevent brute forcing is disabled
// Auth types userpass, ldap and approle support this feature
// precedence: environment var setting >> auth tune setting >> config file setting >> default (enabled)
func (c *Core) isUserLockoutDisabled(mountEntry *MountEntry) (bool, error) {
	if !slices.Contains(configutil.GetSupportedUserLockoutsAuthMethods(), mountEntry.Type) {
		return true, nil
	}

	// check environment variable
	if disableUserLockoutEnv := api.ReadBaoVariable(consts.VaultDisableUserLockout); disableUserLockoutEnv != "" {
		var err error
		disableUserLockout, err := strconv.ParseBool(disableUserLockoutEnv)
		if err != nil {
			return false, errors.New("Error parsing the environment variable BAO_DISABLE_USER_LOCKOUT")
		}
		if disableUserLockout {
			return true, nil
		}
		return false, nil
	}

	// read auth tune for mount entry
	userLockoutConfigFromMount := mountEntry.Config.UserLockoutConfig
	if userLockoutConfigFromMount != nil && userLockoutConfigFromMount.DisableLockout {
		return true, nil
	}

	// read config for auth type from config file
	userLockoutConfiguration := c.getUserLockoutFromConfig(mountEntry.Type)
	if userLockoutConfiguration.DisableLockout {
		return true, nil
	}

	// default
	return false, nil
}

// isUserLocked determines if the login request user is locked
func (c *Core) isUserLocked(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (loginUser *FailedLoginUser, locked bool, err error) {
	// get userFailedLoginInfo map key for login user
	loginUserInfoKey, err := c.getLoginUserInfoKey(ctx, mountEntry, req)
	if err != nil {
		return nil, false, err
	}

	// get entry from userFailedLoginInfo map for the key
	userFailedLoginInfo := c.LocalGetUserFailedLoginInfo(ctx, loginUserInfoKey)

	userLockoutConfiguration := c.getUserLockoutConfiguration(mountEntry)

	switch userFailedLoginInfo {
	case nil:
		// entry not found in userFailedLoginInfo map, check storage to re-verify
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("could not retrieve namespace from context: %w", err)
		}

		view := NamespaceView(c.barrier, ns).SubView(coreLockedUsersPath).SubView(loginUserInfoKey.mountAccessor + "/")
		existingEntry, err := view.Get(ctx, loginUserInfoKey.aliasName)
		if err != nil {
			return nil, false, err
		}

		var lastLoginTime int
		if existingEntry == nil {
			// no storage entry found, user is not locked
			return &loginUserInfoKey, false, nil
		}

		err = jsonutil.DecodeJSON(existingEntry.Value, &lastLoginTime)
		if err != nil {
			return nil, false, err
		}

		// if time passed from last login time is within lockout duration, the user is locked
		if time.Now().Unix()-int64(lastLoginTime) < int64(userLockoutConfiguration.LockoutDuration.Seconds()) {
			// user locked
			return &loginUserInfoKey, true, nil
		}

		// else user is not locked. Entry is stale, this will be removed from storage during cleanup
		// by the background thread

	default:
		// entry found in userFailedLoginInfo map, check if the user is locked
		isCountOverLockoutThreshold := userFailedLoginInfo.count >= uint(userLockoutConfiguration.LockoutThreshold)
		isWithinLockoutDuration := time.Now().Unix()-int64(userFailedLoginInfo.lastFailedLoginTime) < int64(userLockoutConfiguration.LockoutDuration.Seconds())

		if isCountOverLockoutThreshold && isWithinLockoutDuration {
			// user locked
			return &loginUserInfoKey, true, nil
		}
	}

	return &loginUserInfoKey, false, nil
}

// getUserLockoutConfiguration gets the user lockout configuration for a mount entry
// it checks the config file and auth tune values
// precedence: auth tune >> config file values for auth type >> config file values for all type
// >> default user lockout values
// getUserLockoutFromConfig call in this function takes care of config file precedence
func (c *Core) getUserLockoutConfiguration(mountEntry *MountEntry) (userLockoutConfig UserLockoutConfig) {
	// get user configuration values from config file
	userLockoutConfig = c.getUserLockoutFromConfig(mountEntry.Type)

	authTuneUserLockoutConfig := mountEntry.Config.UserLockoutConfig
	// if user lockout is not configured using auth tune, return values from config file
	if authTuneUserLockoutConfig == nil {
		return userLockoutConfig
	}
	// replace values in return with config file configuration
	// for fields that are not configured using auth tune
	if authTuneUserLockoutConfig.LockoutThreshold != 0 {
		userLockoutConfig.LockoutThreshold = authTuneUserLockoutConfig.LockoutThreshold
	}
	if authTuneUserLockoutConfig.LockoutDuration != 0 {
		userLockoutConfig.LockoutDuration = authTuneUserLockoutConfig.LockoutDuration
	}
	if authTuneUserLockoutConfig.LockoutCounterReset != 0 {
		userLockoutConfig.LockoutCounterReset = authTuneUserLockoutConfig.LockoutCounterReset
	}
	if authTuneUserLockoutConfig.DisableLockout {
		userLockoutConfig.DisableLockout = authTuneUserLockoutConfig.DisableLockout
	}
	return userLockoutConfig
}

// getUserLockoutFromConfig gets the userlockout configuration for given mount type from config file
// it reads the user lockout configuration from server config
// it has values for "all" type and any mountType that is configured using config file
// "all" type values are updated in shared config with default values i.e; if "all" type is
// not configured in config file, it is updated in shared config with default configuration
// If "all" type is configured in config file, any missing fields are updated with default values
// similarly missing values for a given mount type in config file are updated with "all" type
// default values
// If user_lockout configuration is not configured using config file at all, defaults are returned
func (c *Core) getUserLockoutFromConfig(mountType string) UserLockoutConfig {
	defaultUserLockoutConfig := UserLockoutConfig{
		LockoutThreshold:    configutil.UserLockoutThresholdDefault,
		LockoutDuration:     configutil.UserLockoutDurationDefault,
		LockoutCounterReset: configutil.UserLockoutCounterResetDefault,
		DisableLockout:      configutil.DisableUserLockoutDefault,
	}
	conf := c.rawConfig.Load()
	if conf == nil {
		return defaultUserLockoutConfig
	}
	userlockouts := conf.(*server.Config).UserLockouts
	if userlockouts == nil {
		return defaultUserLockoutConfig
	}
	for _, userLockoutConfig := range userlockouts {
		switch userLockoutConfig.Type {
		case "all":
			defaultUserLockoutConfig = UserLockoutConfig{
				LockoutThreshold:    userLockoutConfig.LockoutThreshold,
				LockoutDuration:     userLockoutConfig.LockoutDuration,
				LockoutCounterReset: userLockoutConfig.LockoutCounterReset,
				DisableLockout:      userLockoutConfig.DisableLockout,
			}
		case mountType:
			return UserLockoutConfig{
				LockoutThreshold:    userLockoutConfig.LockoutThreshold,
				LockoutDuration:     userLockoutConfig.LockoutDuration,
				LockoutCounterReset: userLockoutConfig.LockoutCounterReset,
				DisableLockout:      userLockoutConfig.DisableLockout,
			}

		}
	}
	return defaultUserLockoutConfig
}

func (c *Core) buildMfaEnforcementResponse(eConfig *mfa.MFAEnforcementConfig) (*logical.MFAConstraintAny, error) {
	mfaAny := &logical.MFAConstraintAny{
		Any: []*logical.MFAMethodID{},
	}
	for _, methodID := range eConfig.MFAMethodIDs {
		mConfig, err := c.loginMFABackend.MemDBMFAConfigByID(methodID)
		if err != nil {
			return nil, fmt.Errorf("failed to get methodID %s from MFA config table, error: %v", methodID, err)
		}
		var duoUsePasscode bool
		if mConfig.Type == mfaMethodTypeDuo {
			duoConf, ok := mConfig.Config.(*mfa.Config_DuoConfig)
			if !ok {
				return nil, errors.New("invalid MFA configuration type")
			}
			duoUsePasscode = duoConf.DuoConfig.UsePasscode
		}
		mfaMethod := &logical.MFAMethodID{
			Type:         mConfig.Type,
			ID:           methodID,
			UsesPasscode: mConfig.Type == mfaMethodTypeTOTP || duoUsePasscode,
			Name:         mConfig.Name,
		}
		mfaAny.Any = append(mfaAny.Any, mfaMethod)
	}
	return mfaAny, nil
}

// RegisterAuth uses a logical.Auth object to create a token entry in the token
// store, and registers a corresponding token lease to the expiration manager.
// role is the login role used as part of the creation of the token entry. If not
// relevant, can be omitted (by being provided as "").
func (c *Core) RegisterAuth(ctx context.Context, tokenTTL time.Duration, path string, auth *logical.Auth, role string, persistToken bool, userLockoutInfo *FailedLoginUser) (*logical.TokenEntry, error) {
	// We first assign token policies to what was returned from the backend
	// via auth.Policies. Then, we get the full set of policies into
	// auth.Policies from the backend + entity information -- this is not
	// stored in the token, but we perform sanity checks on it and return
	// that information to the user.

	// Generate a token
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	te := logical.TokenEntry{
		Path:           path,
		Meta:           auth.Metadata,
		DisplayName:    auth.DisplayName,
		CreationTime:   time.Now().Unix(),
		TTL:            tokenTTL,
		NumUses:        auth.NumUses,
		EntityID:       auth.EntityID,
		BoundCIDRs:     auth.BoundCIDRs,
		Policies:       auth.TokenPolicies,
		NamespaceID:    ns.ID,
		ExplicitMaxTTL: auth.ExplicitMaxTTL,
		Period:         auth.Period,
		Type:           auth.TokenType,
	}

	if te.TTL == 0 && (len(te.Policies) != 1 || te.Policies[0] != "root") {
		c.logger.Error("refusing to create a non-root zero TTL token")
		return nil, ErrInternalError
	}

	if c.standby && persistToken {
		return nil, logical.ErrPerfStandbyPleaseForward
	}

	if err := c.tokenStore.create(ctx, &te, persistToken); err != nil {
		c.logger.Error("failed to create token", "error", err)
		return nil, ErrInternalError
	}

	// Populate the client token, accessor, and TTL
	auth.ClientToken = te.ID
	auth.Accessor = te.Accessor
	auth.TTL = te.TTL
	auth.Orphan = te.Parent == ""

	switch auth.TokenType {
	case logical.TokenTypeBatch:
		// Ensure it's not marked renewable since it isn't
		auth.Renewable = false
	case logical.TokenTypeService:
		// Register with the expiration manager
		if err := c.expiration.RegisterAuth(ctx, &te, auth, role, persistToken); err != nil {
			if err := c.tokenStore.revokeOrphan(ctx, te.ID); err != nil {
				c.logger.Warn("failed to clean up token lease during login request", "request_path", path, "error", err)
			}
			c.logger.Error("failed to register token lease during login request", "request_path", path, "error", err)
			return nil, ErrInternalError
		}
		if te.ExternalID != "" {
			auth.ClientToken = te.ExternalID
		}
		// Successful login, remove any entry from userFailedLoginInfo map
		// if it exists. This is done for service tokens (for oss) here.
		// For ent it is taken care by registerAuth RPC calls.
		if userLockoutInfo != nil {
			// We don't need to try to delete the lockedUsers storage entry, since we're
			// processing a login request. If a login attempt is allowed, it means the user is
			// unlocked and we only add storage entry when the user gets locked.
			err = c.LocalUpdateUserFailedLoginInfo(ctx, *userLockoutInfo, nil, true)
			if err != nil {
				return nil, err
			}
		}
	}
	return &te, nil
}

// LocalGetUserFailedLoginInfo gets the failed login information for a user based on alias name and mountAccessor
func (c *Core) LocalGetUserFailedLoginInfo(ctx context.Context, userKey FailedLoginUser) *FailedLoginInfo {
	c.userFailedLoginInfoLock.Lock()
	value, exists := c.userFailedLoginInfo[userKey]
	c.userFailedLoginInfoLock.Unlock()
	if exists {
		return value
	}
	return nil
}

// LocalUpdateUserFailedLoginInfo updates the failed login information for a user based on alias name and mountAccessor
func (c *Core) LocalUpdateUserFailedLoginInfo(ctx context.Context, userKey FailedLoginUser, failedLoginInfo *FailedLoginInfo, deleteEntry bool) error {
	c.userFailedLoginInfoLock.Lock()
	defer c.userFailedLoginInfoLock.Unlock()

	if deleteEntry {
		// delete the entry from the map, if no key exists it is no-op
		delete(c.userFailedLoginInfo, userKey)
		return nil
	}

	// update entry in the map
	c.userFailedLoginInfo[userKey] = failedLoginInfo

	// get the user lockout configuration for the user
	mountEntry := c.router.MatchingMountByAccessor(userKey.mountAccessor)
	if mountEntry == nil {
		mountEntry = &MountEntry{namespace: namespace.RootNamespace}
	}
	userLockoutConfiguration := c.getUserLockoutConfiguration(mountEntry)

	// if failed login count has reached threshold, create a storage entry as the user got locked
	if failedLoginInfo.count >= uint(userLockoutConfiguration.LockoutThreshold) {
		// user locked
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(failedLoginInfo.lastFailedLoginTime, nil)
		if err != nil {
			c.logger.Error("failed to encode or compress failed login user entry", "namespace", mountEntry.namespace.Path, "error", err)
			return err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   userKey.aliasName,
			Value: compressedBytes,
		}

		// Write to the physical backend
		view := NamespaceView(c.barrier, mountEntry.namespace).SubView(coreLockedUsersPath).SubView(userKey.mountAccessor + "/")
		if err := view.Put(ctx, entry); err != nil {
			c.logger.Error("failed to persist failed login user entry", "namespace", mountEntry.namespace.Path, "error", err)
			return err
		}

	}

	return nil
}

// PopulateTokenEntry looks up req.ClientToken in the token store and uses
// it to set other fields in req.  Does nothing if ClientToken is empty
// or a JWT token, or for service tokens that don't exist in the token store.
// Should be called with read stateLock held.
func (c *Core) PopulateTokenEntry(ctx context.Context, req *logical.Request) error {
	if req.ClientToken == "" {
		return nil
	}

	// Also attach the accessor if we have it. This doesn't fail if it
	// doesn't exist because the request may be to an unauthenticated
	// endpoint/login endpoint where a bad current token doesn't matter, or
	// a token from a Vault version pre-accessors. We ignore errors for
	// JWTs.
	token := req.ClientToken
	var err error
	req.InboundSSCToken = token
	decodedToken := token
	if IsSSCToken(token) {
		// If ForwardToActive is set to ForwardSSCTokenToActive, we ignore
		// whether the endpoint is a login request, as since we have the token
		// forwarded to us, we should treat it as an unauthenticated endpoint
		// and ensure the token is populated too regardless.
		// Notably, this is important for some endpoints, such as endpoints
		// such as sys/ui/mounts/internal, which is unauthenticated but a token
		// may be provided to be used.
		// Without the check to see if
		// c.ForwardToActive() == ForwardSSCTokenToActive unauthenticated
		// requests that do not use a token but were provided one anyway
		// could fail with a 412.
		// We only follow this behaviour if we're a perf standby, as
		// this behaviour only makes sense in that case as only they
		// could be missing the token population.
		// Without ForwardToActive being set to ForwardSSCTokenToActive,
		// behaviours that rely on this functionality also wouldn't make
		// much sense, as they would fail with 412 required index not present
		// as perf standbys aren't guaranteed to have the WAL state
		// for new tokens.
		unauth := c.isLoginRequest(ctx, req)
		decodedToken, err = c.CheckSSCToken(ctx, token, unauth)
		// If we receive an error from CheckSSCToken, we can assume the token is bad somehow, and the client
		// should receive a 403 bad token error like they do for all other invalid tokens, unless the error
		// specifies that we should forward the request or retry the request.
		if err != nil {
			return logical.ErrPermissionDenied
		}
	}
	req.ClientToken = decodedToken
	// We ignore the token returned from CheckSSCToken here as Lookup also
	// decodes the SSCT, and it may need the original SSCT to check state.
	te, err := c.LookupToken(ctx, token)
	if err != nil {
		if errors.Is(err, logical.ErrPerfStandbyPleaseForward) {
			return err
		}
		// If we have two dots but the second char is a dot it's a vault
		// token of the form s.SOMETHING.nsid, not a JWT
		if !IsJWT(token) {
			return fmt.Errorf("error performing token check: %w", err)
		}
	}
	if err == nil && te != nil {
		req.ClientTokenAccessor = te.Accessor
		req.ClientTokenRemainingUses = te.NumUses
		req.SetTokenEntry(te)
	}
	return nil
}

func (c *Core) CheckSSCToken(ctx context.Context, token string, unauth bool) (string, error) {
	if unauth && token != "" {
		// This token shouldn't really be here, but alas it was sent along with the request
		// Since we're already knee deep in the token checking code pre-existing token checking
		// code, we have to deal with this token whether we like it or not. So, we'll just try
		// to get the inner token, and if that fails, return the token as-is. We intentionally
		// will skip any token checks, because this is an unauthenticated paths and the token
		// is just a nuisance rather than a means of auth.

		// We cannot return whatever we like here, because if we do then CheckToken, which looks up
		// the corresponding lease, will not find the token entry and lease. There are unauth'ed
		// endpoints that use the token entry (such as sys/ui/mounts/internal) to do custom token
		// checks, which would then fail. Therefore, we must try to get whatever thing is tied to
		// token entries, but we must explicitly not do any SSC Token checks.
		tok, err := c.DecodeSSCToken(token)
		if err != nil || tok == "" {
			return token, nil
		}
		return tok, nil
	}
	return c.checkSSCTokenInternal(ctx, token)
}

// DecodeSSCToken returns the random part of an SSCToken without
// performing any signature or WAL checks.
func (c *Core) DecodeSSCToken(token string) (string, error) {
	// Skip batch and old style service tokens. These can have the prefix "b.",
	// "s." (for old tokens) or "hvb."
	if !IsSSCToken(token) {
		return token, nil
	}
	tok, err := c.DecodeSSCTokenInternal(token)
	if err != nil {
		return "", err
	}
	return tok.Random, nil
}

// DecodeSSCTokenInternal is a helper used to get the inner part of a SSC token without
// checking the token signature or the WAL index.
func (c *Core) DecodeSSCTokenInternal(token string) (*tokens.Token, error) {
	signedToken := &tokens.SignedToken{}

	// Skip batch and old style service tokens. These can have the prefix "b.",
	// "s." (for old tokens) or "hvb."
	if !strings.HasPrefix(token, consts.ServiceTokenPrefix) {
		return nil, errors.New("not service token")
	}

	// Consider the suffix of the token only when unmarshalling
	suffixToken := token[4:]

	tokenBytes, err := base64.RawURLEncoding.DecodeString(suffixToken)
	if err != nil {
		return nil, errors.New("can't decode token")
	}

	err = proto.Unmarshal(tokenBytes, signedToken)
	if err != nil {
		return nil, err
	}
	plainToken := &tokens.Token{}
	err2 := proto.Unmarshal([]byte(signedToken.Token), plainToken)
	if err2 != nil {
		return nil, err2
	}
	return plainToken, nil
}

func (c *Core) checkSSCTokenInternal(ctx context.Context, token string) (string, error) {
	signedToken := &tokens.SignedToken{}

	// Skip batch and old style service tokens. These can have the prefix "b.",
	// "s." (for old tokens) or "hvb."
	if !strings.HasPrefix(token, consts.ServiceTokenPrefix) {
		return token, nil
	}

	// Check token length to guess if this is an server side consistent token or not.
	// Note that even when the DisableSSCTokens flag is set, index
	// bearing tokens that have already been given out may still be used.
	if !IsSSCToken(token) {
		return token, nil
	}

	// Consider the suffix of the token only when unmarshalling
	suffixToken := token[4:]

	tokenBytes, err := base64.RawURLEncoding.DecodeString(suffixToken)
	if err != nil {
		c.logger.Warn("cannot decode token", "error", err)
		return token, nil
	}

	err = proto.Unmarshal(tokenBytes, signedToken)
	if err != nil {
		return "", fmt.Errorf("error occurred when unmarshalling ssc token: %w", err)
	}
	hm, err := c.tokenStore.CalculateSignedTokenHMAC(signedToken.Token)
	if !hmac.Equal(hm, signedToken.Hmac) {
		return "", fmt.Errorf("token mac for %+v is incorrect: err %w", signedToken, err)
	}
	plainToken := &tokens.Token{}
	err = proto.Unmarshal([]byte(signedToken.Token), plainToken)
	if err != nil {
		return "", err
	}

	ep := int(plainToken.IndexEpoch)
	if ep < c.tokenStore.GetSSCTokensGenerationCounter() {
		return plainToken.Random, nil
	}

	return plainToken.Random, nil
}
