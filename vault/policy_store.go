// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// policySubPath is the sub-path used for the policy store view. This is
	// nested under the system view.
	policyACLSubPath = "policy/"

	// policyCacheSize is the number of policies that are kept cached
	policyCacheSize = 1024

	// defaultPolicyName is the name of the default policy
	defaultPolicyName = "default"

	// responseWrappingPolicyName is the name of the fixed policy
	responseWrappingPolicyName = "response-wrapping"

	// responseWrappingPolicy is the policy that ensures cubbyhole response
	// wrapping can always succeed.
	responseWrappingPolicy = `
path "cubbyhole/response" {
    capabilities = ["create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
`
	// defaultPolicy is the "default" policy
	defaultPolicy = `
# Allow tokens to look up their own properties
path "auth/token/lookup-self" {
    capabilities = ["read"]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own capabilities on a path
path "sys/capabilities-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own entity by id or name
path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read"]
}
path "identity/entity/name/{{identity.entity.name}}" {
  capabilities = ["read"]
}


# Allow a token to look up its resultant ACL from all policies. This is useful
# for UIs. It is an internal path because the format may change at any time
# based on how the internal ACL features and capabilities change.
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# Allow a token to renew a lease via lease_id in the request body; old path for
# old clients, new path for newer
path "sys/renew" {
    capabilities = ["update"]
}
path "sys/leases/renew" {
    capabilities = ["update"]
}

# Allow looking up lease properties. This requires knowing the lease ID ahead
# of time and does not divulge any sensitive information.
path "sys/leases/lookup" {
    capabilities = ["update"]
}

# Allow a token to manage its own cubbyhole
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow a token to wrap arbitrary values in a response-wrapping token
path "sys/wrapping/wrap" {
    capabilities = ["update"]
}

# Allow a token to look up the creation time and TTL of a given
# response-wrapping token
path "sys/wrapping/lookup" {
    capabilities = ["update"]
}

# Allow a token to unwrap a response-wrapping token. This is a convenience to
# avoid client token swapping since this is also part of the response wrapping
# policy.
path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}

# Allow general purpose tools
path "sys/tools/hash" {
    capabilities = ["update"]
}
path "sys/tools/hash/*" {
    capabilities = ["update"]
}

# Allow a token to make requests to the Authorization Endpoint for OIDC providers.
path "identity/oidc/provider/+/authorize" {
    capabilities = ["read", "update"]
}
`
)

var (
	immutablePolicies = []string{
		"root",
		responseWrappingPolicyName,
	}
	nonAssignablePolicies = []string{
		responseWrappingPolicyName,
	}
)

// PolicyStore is used to provide durable storage of policy, and to
// manage ACLs associated with them.
type PolicyStore struct {
	core *Core

	tokenPoliciesLRU *lru.TwoQueueCache[string, *Policy]

	// This is used to ensure that writes to the store (acl) or to the egp
	// path tree don't happen concurrently. We are okay reading stale data so
	// long as there aren't concurrent writes.
	modifyLock *sync.RWMutex

	// logger is the server logger copied over from core
	logger log.Logger
}

// PolicyEntry is used to store a policy by name
type PolicyEntry struct {
	Version     int
	DataVersion int
	CASRequired bool
	Raw         string
	Templated   bool
	Type        PolicyType
	Expiration  time.Time
	Modified    time.Time
}

// NewPolicyStore creates a new PolicyStore that is backed
// using a given view. It used used to durable store and manage named policy.
func NewPolicyStore(ctx context.Context, core *Core, baseView BarrierView, system logical.SystemView, logger log.Logger) (*PolicyStore, error) {
	ps := &PolicyStore{
		modifyLock: new(sync.RWMutex),
		logger:     logger,
		core:       core,
	}

	if !system.CachingDisabled() {
		cache, _ := lru.New2Q[string, *Policy](policyCacheSize)
		ps.tokenPoliciesLRU = cache
	}

	return ps, nil
}

// setupPolicyStore is used to initialize the policy store
// when the vault is being unsealed.
func (c *Core) setupPolicyStore(ctx context.Context) error {
	// Create the policy store
	var err error
	sysView := &dynamicSystemView{core: c}
	psLogger := c.baseLogger.Named("policy")
	c.AddLogger(psLogger)
	c.policyStore, err = NewPolicyStore(ctx, c, c.systemBarrierView, sysView, psLogger)
	if err != nil {
		return err
	}

	// Ensure that the default policy exists, and if not, create it
	if err := c.policyStore.loadDefaultPolicies(ctx); err != nil {
		return err
	}

	return nil
}

// teardownPolicyStore is used to reverse setupPolicyStore
// when the vault is being sealed.
func (c *Core) teardownPolicyStore() error {
	c.policyStore = nil
	return nil
}

func (ps *PolicyStore) invalidateNamespace(ctx context.Context, uuid string) error {
	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	for _, key := range ps.tokenPoliciesLRU.Keys() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(key, uuid) {
			ps.tokenPoliciesLRU.Remove(key)
		}
	}

	return nil
}

func (ps *PolicyStore) invalidate(ctx context.Context, name string, policyType PolicyType) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		ps.logger.Error("unable to invalidate key, no namespace info passed", "key", name)
		return nil
	}

	// This may come with a prefixed "/" due to joining the file path
	saneName := strings.TrimPrefix(name, "/")
	index := ps.cacheKey(ns, saneName)

	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	// We don't lock before removing from the LRU here because the worst that
	// can happen is we load again if something since added it
	switch policyType {
	case PolicyTypeACL:
		if ps.tokenPoliciesLRU != nil {
			ps.tokenPoliciesLRU.Remove(index)
		}

	default:
		// Can't do anything
		return nil
	}

	// Force a reload
	out, err := ps.switchedGetPolicy(ctx, name, policyType, false)
	if err != nil {
		ps.logger.Error("error fetching policy after invalidation", "name", saneName)
	}

	// If true, the invalidation was actually a delete, so we may need to
	// perform further deletion tasks. We skip the physical deletion just in
	// case another process has re-written the policy; instead next time Get is
	// called the values will be loaded back in.
	if out == nil {
		ps.switchedDeletePolicy(ctx, name, policyType, false, true)
	}

	return nil
}

// SetPolicy is used to create or update the given policy
func (ps *PolicyStore) SetPolicy(ctx context.Context, p *Policy, casVersion *int) error {
	defer metrics.MeasureSince([]string{"policy", "set_policy"}, time.Now())
	if p == nil {
		return errors.New("nil policy passed in for storage")
	}
	if p.Name == "" {
		return errors.New("policy name missing")
	}
	// Policies are normalized to lower-case
	p.Name = ps.sanitizeName(p.Name)
	if slices.Contains(immutablePolicies, p.Name) {
		return fmt.Errorf("cannot update %q policy", p.Name)
	}

	return ps.setPolicyInternal(ctx, p, casVersion)
}

func (ps *PolicyStore) setPolicyInternal(ctx context.Context, p *Policy, casVersion *int) error {
	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	// Get the appropriate view based on policy type and namespace
	view := ps.getBarrierView(p.namespace, p.Type)

	p.Modified = time.Now()

	existingEntry, err := view.Get(ctx, p.Name)
	if err != nil {
		return fmt.Errorf("unable to get existing policy for check-and-set: %w", err)
	}

	var existing PolicyEntry
	if existingEntry != nil {
		if err := existingEntry.DecodeJSON(&existing); err != nil {
			return fmt.Errorf("failed to decode existing policy: %w", err)
		}
	}

	casRequired := existing.CASRequired || p.CASRequired
	if casVersion == nil && casRequired {
		return fmt.Errorf("check-and-set parameter required for this call")
	}
	if casVersion != nil {
		if *casVersion == -1 && existingEntry != nil {
			return fmt.Errorf("check-and-set parameter set to -1 on existing entry")
		}

		if *casVersion != -1 && *casVersion != existing.DataVersion {
			return fmt.Errorf("check-and-set parameter did not match the current version")
		}
	}

	// Create the entry
	p.DataVersion = existing.DataVersion + 1
	entry, err := logical.StorageEntryJSON(p.Name, &PolicyEntry{
		Version:     2,
		DataVersion: p.DataVersion,
		CASRequired: p.CASRequired,
		Raw:         p.Raw,
		Type:        p.Type,
		Templated:   p.Templated,
		Expiration:  p.Expiration,
		Modified:    p.Modified,
	})
	if err != nil {
		return fmt.Errorf("failed to create entry: %w", err)
	}

	// Construct the cache key
	index := ps.cacheKey(p.namespace, p.Name)

	switch p.Type {
	case PolicyTypeACL:
		if err := view.Put(ctx, entry); err != nil {
			return fmt.Errorf("failed to persist policy: %w", err)
		}

		if ps.tokenPoliciesLRU != nil {
			ps.tokenPoliciesLRU.Add(index, p)
		}
	default:
		return errors.New("unknown policy type, cannot set")
	}

	return nil
}

// GetNonEGPPolicyType returns a policy's type.
// It will return an error if the policy doesn't exist in the store or isn't
// an ACL.
func (ps *PolicyStore) GetNonEGPPolicyType(ctx context.Context, name string) (*PolicyType, error) {
	// We only support ACL policies at the moment.
	policy, err := ps.GetPolicy(ctx, name, PolicyTypeACL)
	if err != nil {
		return nil, err
	}

	if policy == nil {
		return nil, ErrPolicyNotExist
	}

	return &policy.Type, nil
}

// getACLView returns the ACL view for the given namespace
func (ps *PolicyStore) getACLView(ns *namespace.Namespace) BarrierView {
	if ns.ID == namespace.RootNamespaceID {
		return ps.core.systemBarrierView.SubView(policyACLSubPath)
	}

	return ps.core.namespaceMountEntryView(ns, systemBarrierPrefix+policyACLSubPath)
}

// getBarrierView returns the appropriate barrier view for the given namespace and policy type.
// Currently, this only supports ACL policies, so it delegates to getACLView.
func (ps *PolicyStore) getBarrierView(ns *namespace.Namespace, _ PolicyType) BarrierView {
	return ps.getACLView(ns)
}

// GetPolicy is used to fetch the named policy
func (ps *PolicyStore) GetPolicy(ctx context.Context, name string, policyType PolicyType) (*Policy, error) {
	return ps.switchedGetPolicy(ctx, name, policyType, true)
}

func (ps *PolicyStore) switchedGetPolicy(ctx context.Context, name string, policyType PolicyType, grabLock bool) (*Policy, error) {
	defer metrics.MeasureSince([]string{"policy", "get_policy"}, time.Now())

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	var cache *lru.TwoQueueCache[string, *Policy]
	var view BarrierView

	switch policyType {
	case PolicyTypeACL, PolicyTypeToken:
		cache = ps.tokenPoliciesLRU
		view = ps.getACLView(ns)
		policyType = PolicyTypeACL
	}

	if cache != nil {
		// Check for cached policy.
		if raw, ok := cache.Get(index); ok {
			// Check for expiration of cached policy.
			if !raw.Expiration.IsZero() && time.Now().After(raw.Expiration) {
				// Only remove the entry from cache; we have not locked the
				// store so a change might have modified it but hasn't yet
				// invalidated the cache entry.
				//
				// We remove it from cache and fall through to fetching the
				// actual policy here.
				cache.Remove(index)
			} else {
				return raw, nil
			}
		}
	}

	// Special case the root policy
	if policyType == PolicyTypeACL && name == "root" && ns.ID == namespace.RootNamespaceID {
		p := &Policy{
			Name:      "root",
			namespace: namespace.RootNamespace,
			Type:      PolicyTypeACL,
		}
		if cache != nil {
			cache.Add(index, p)
		}
		return p, nil
	}

	if grabLock {
		ps.modifyLock.Lock()
		defer ps.modifyLock.Unlock()
	}

	// See if anything has added it since we got the lock. At this point,
	// any subsequent writes would be committed, so if this policy were then
	// read ahead of us getting the write lock, it would be up-to-date (as
	// write would've removed the policy). However, all this could've occurred
	// after our earlier cache read above.
	if cache != nil {
		if raw, ok := cache.Get(index); ok {
			// Check for expiration of cached policy.
			if !raw.Expiration.IsZero() && time.Now().After(raw.Expiration) {
				// This is an odd edge case. We have the entry in cache and we
				// know nobody else has yet modified it in storage, otherwise
				// we wouldn't have held the modifyLock. Remove it both from
				// cache and from storage.
				if err := view.Delete(ctx, name); err != nil {
					return nil, fmt.Errorf("failed to remove expired policy: %w", err)
				}

				cache.Remove(index)
				return nil, nil
			}

			return raw, nil
		}
	}

	// Nil-check on the view before proceeding to retrieve from storage
	if view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for policy type %q", policyType)
	}

	out, err := view.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	if out == nil {
		return nil, nil
	}

	policyEntry := new(PolicyEntry)
	policy := new(Policy)
	err = out.DecodeJSON(policyEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Handle expiration, removing the entry if it is expired.
	if !policyEntry.Expiration.IsZero() && time.Now().After(policyEntry.Expiration) {
		if err := view.Delete(ctx, name); err != nil {
			return nil, fmt.Errorf("failed to remove expired policy: %w", err)
		}

		return nil, nil
	}

	// Set these up here so that they're available for loading into
	// Sentinel
	policy.Name = name
	policy.DataVersion = policyEntry.DataVersion
	policy.CASRequired = policyEntry.CASRequired
	policy.Raw = policyEntry.Raw
	policy.Type = policyEntry.Type
	policy.Templated = policyEntry.Templated
	policy.Expiration = policyEntry.Expiration
	policy.Modified = policyEntry.Modified
	policy.namespace = ns
	switch policyEntry.Type {
	case PolicyTypeACL:
		// Parse normally
		p, err := ParseACLPolicy(ns, policyEntry.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy: %w", err)
		}
		policy.Paths = p.Paths

		// Reset this in case they set the name in the policy itself
		policy.Name = name
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyEntry.Type.String())
	}

	if cache != nil {
		// Update the LRU cache
		cache.Add(index, policy)
	}

	return policy, nil
}

// ListPolicies is used to list the available policies
func (ps *PolicyStore) ListPolicies(ctx context.Context, policyType PolicyType, omitNonAssignable bool) ([]string, error) {
	return ps.ListPoliciesWithPrefix(ctx, policyType, "", omitNonAssignable)
}

// ListPoliciesWithPrefix is used to list policies with the given prefix in the specified namespace
// omitNonAssignable dictates whether result list
// should also contain the nonAssignable policies
func (ps *PolicyStore) ListPoliciesWithPrefix(ctx context.Context, policyType PolicyType, prefix string, omitNonAssignable bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"policy", "list_policies"}, time.Now())

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, namespace.ErrNoNamespace
	}

	// Get the appropriate view based on policy type and namespace
	view := ps.getBarrierView(ns, policyType)

	// Scan the view, since the policy names are the same as the
	// key names.
	var keys []string
	switch policyType {
	case PolicyTypeACL:
		keys, err = logical.CollectKeysWithPrefix(ctx, view, prefix)
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyType)
	}

	if omitNonAssignable {
		keys = slices.DeleteFunc(keys, func(policyName string) bool {
			return slices.Contains(nonAssignablePolicies, policyName)
		})
	}

	return keys, err
}

// DeletePolicy is used to delete the named policy
func (ps *PolicyStore) DeletePolicy(ctx context.Context, name string, policyType PolicyType) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, false)
}

// deletePolicyForce is used to delete the named policy and force it even if
// default or a singleton. It's used for invalidations or namespace deletion
// where we internally need to actually remove a policy that the user normally
// isn't allowed to remove.
func (ps *PolicyStore) deletePolicyForce(ctx context.Context, name string, policyType PolicyType) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, true)
}

func (ps *PolicyStore) switchedDeletePolicy(ctx context.Context, name string, policyType PolicyType, physicalDeletion, force bool) error {
	defer metrics.MeasureSince([]string{"policy", "delete_policy"}, time.Now())

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	// If not set, the call comes from invalidation, where we'll already have
	// grabbed the lock
	if physicalDeletion {
		ps.modifyLock.Lock()
		defer ps.modifyLock.Unlock()
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	view := ps.getBarrierView(ns, policyType)

	switch policyType {
	case PolicyTypeACL:
		if !force {
			if slices.Contains(immutablePolicies, name) {
				return fmt.Errorf("cannot delete %q policy", name)
			}
			if name == "default" {
				return errors.New("cannot delete default policy")
			}
		}

		if physicalDeletion {
			err := view.Delete(ctx, name)
			if err != nil {
				return fmt.Errorf("failed to delete policy: %w", err)
			}
		}

		if ps.tokenPoliciesLRU != nil {
			// Clear the cache
			ps.tokenPoliciesLRU.Remove(index)
		}
	}

	return nil
}

// ACL is used to return an ACL which is built using the
// named policies and pre-fetched policies if given.
func (ps *PolicyStore) ACL(ctx context.Context, entity *identity.Entity, policyNames map[string][]string, additionalPolicies ...*Policy) (*ACL, error) {
	var allPolicies []*Policy

	// Fetch the named policies
	for nsID, nsPolicyNames := range policyNames {
		policyNS, err := ps.core.NamespaceByID(ctx, nsID)
		if err != nil {
			return nil, err
		}
		if policyNS == nil {
			return nil, namespace.ErrNoNamespace
		}
		policyCtx := namespace.ContextWithNamespace(ctx, policyNS)
		for _, nsPolicyName := range nsPolicyNames {
			p, err := ps.GetPolicy(policyCtx, nsPolicyName, PolicyTypeToken)
			if err != nil {
				return nil, fmt.Errorf("failed to get policy: %w", err)
			}
			if p != nil {
				allPolicies = append(allPolicies, p)
			}
		}
	}

	// Append any pre-fetched policies that were given
	allPolicies = append(allPolicies, additionalPolicies...)

	var fetchedGroups bool
	var groups []*identity.Group
	for i, policy := range allPolicies {
		if policy.Type == PolicyTypeACL && policy.Templated {
			if !fetchedGroups {
				fetchedGroups = true
				if entity != nil {
					directGroups, inheritedGroups, err := ps.core.identityStore.groupsByEntityID(ctx, entity.ID)
					if err != nil {
						return nil, fmt.Errorf("failed to fetch group memberships: %w", err)
					}
					groups = append(directGroups, inheritedGroups...)
				}
			}
			p, err := parseACLPolicyWithTemplating(policy.namespace, policy.Raw, true, entity, groups)
			if err != nil {
				return nil, fmt.Errorf("error parsing templated policy %q: %w", policy.Name, err)
			}
			p.Name = policy.Name
			allPolicies[i] = p
		}
	}

	// Construct the ACL
	acl, err := NewACL(ctx, allPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to construct ACL: %w", err)
	}

	return acl, nil
}

// loadACLPolicy is used to load default ACL policies in a specific
// namespace.
func (ps *PolicyStore) loadACLPolicy(ctx context.Context, policyName, policyText string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Check if the policy already exists
	policy, err := ps.GetPolicy(ctx, policyName, PolicyTypeACL)
	if err != nil {
		return fmt.Errorf("error fetching %s policy from store: %w", policyName, err)
	}
	if policy != nil {
		if !slices.Contains(immutablePolicies, policyName) || policyText == policy.Raw {
			return nil
		}
	}

	policy, err = ParseACLPolicy(ns, policyText)
	if err != nil {
		return fmt.Errorf("error parsing %s policy: %w", policyName, err)
	}

	if policy == nil {
		return fmt.Errorf("parsing %q policy resulted in nil policy", policyName)
	}

	cas := &policy.DataVersion
	policy.Name = policyName
	policy.Type = PolicyTypeACL
	return ps.setPolicyInternal(ctx, policy, cas)
}

func (ps *PolicyStore) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (ps *PolicyStore) cacheKey(ns *namespace.Namespace, name string) string {
	return path.Join(ns.UUID, name)
}

// loadDefaultPolicies loads default policies for the namespace in the provided context
func (ps *PolicyStore) loadDefaultPolicies(ctx context.Context) error {
	// Load the default policy into the namespace
	if err := ps.loadACLPolicy(ctx, defaultPolicyName, defaultPolicy); err != nil {
		return fmt.Errorf("failed to load default policy: %w", err)
	}

	// Load the response wrapping policy into the namespace
	if err := ps.loadACLPolicy(ctx, responseWrappingPolicyName, responseWrappingPolicy); err != nil {
		return fmt.Errorf("failed to load response wrapping policy: %w", err)
	}

	return nil
}
