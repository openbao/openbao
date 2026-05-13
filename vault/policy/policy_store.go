// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package policy

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	vaultidentity "github.com/openbao/openbao/vault/identity"
)

var ErrPolicyNotExist = errors.New("policy does not exist")

const (
	// policySubPath is the sub-path used for the policy store view. This is
	// nested under the system view.
	ACLSubPath = "policy/"

	// policyCacheSize is the number of policies that are kept cached
	policyCacheSize = 1024

	// defaultPolicyName is the name of the default policy
	defaultPolicyName = "default"

	// ResponseWrappingPolicyName is the name of the fixed policy
	ResponseWrappingPolicyName = "response-wrapping"

	// ResponseWrappingPolicy is the policy that ensures cubbyhole response
	// wrapping can always succeed.
	ResponseWrappingPolicy = `
path "cubbyhole/response" {
    capabilities = ["create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
`
	// DefaultPolicy is the "default" policy
	DefaultPolicy = `
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
		ResponseWrappingPolicyName,
	}
	NonAssignablePolicies = []string{
		ResponseWrappingPolicyName,
	}
)

// Store is used to provide durable storage of policy, and to
// manage ACLs associated with them.
type Store struct {
	core core

	tokenPoliciesLRU *lru.TwoQueueCache[string, *Policy]

	// This is used to ensure that writes to the store (acl) or to the egp
	// path tree don't happen concurrently. We are okay reading stale data so
	// long as there aren't concurrent writes.
	modifyLocks []*locksutil.LockEntry

	// logger is the server logger copied over from core
	logger log.Logger
}

// Entry is used to store a policy by name
type Entry struct {
	Version     int
	DataVersion int
	CASRequired bool
	Raw         string
	Templated   bool
	Type        Type
	Expiration  time.Time
	Modified    time.Time
}

type core interface {
	NamespaceByID(context.Context, string) (*namespace.Namespace, error)
	IdentityStore() *vaultidentity.IdentityStore
	NamespaceView(*namespace.Namespace) barrier.View
}

// NewStore creates a new PolicyStore that is backed
// using a given view. It used used to durable store and manage named policy.
func NewStore(ctx context.Context, core core, baseView barrier.View, system logical.SystemView, logger log.Logger) (*Store, error) {
	ps := &Store{
		modifyLocks: locksutil.CreateLocks(),
		logger:      logger,
		core:        core,
	}

	if !system.CachingDisabled() {
		cache, _ := lru.New2Q[string, *Policy](policyCacheSize)
		ps.tokenPoliciesLRU = cache
	}

	return ps, nil
}

func (ps *Store) lockWithUnlock(ctx context.Context) func() {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		ns = namespace.RootNamespace
	}

	lock := locksutil.LockForKey(ps.modifyLocks, ns.UUID)

	ps.logger.Trace("acquiring lock for", "namespace", ns.UUID)
	lock.Lock()
	return lock.Unlock
}

func (ps *Store) rLockWithUnlock(ctx context.Context) func() {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		ns = namespace.RootNamespace
	}

	lock := locksutil.LockForKey(ps.modifyLocks, ns.UUID)

	ps.logger.Trace("acquiring lock for", "namespace", ns.UUID)
	lock.RLock()
	return lock.RUnlock
}

func (ps *Store) InvalidateNamespace(ctx context.Context, uuid string) {
	// Skip invalidation if no cache exists.
	if ps.tokenPoliciesLRU == nil {
		return
	}

	defer ps.lockWithUnlock(ctx)()

	for _, key := range ps.tokenPoliciesLRU.Keys() {
		if strings.HasPrefix(key, uuid) {
			ps.tokenPoliciesLRU.Remove(key)
		}
	}
}

func (ps *Store) Invalidate(ctx context.Context, name string, policyType Type) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// This may come with a prefixed "/" due to joining the file path
	saneName := strings.TrimPrefix(name, "/")
	index := ps.cacheKey(ns, saneName)

	defer ps.lockWithUnlock(ctx)()

	// We don't lock before removing from the LRU here because the worst that
	// can happen is we load again if something since added it
	switch policyType {
	case TypeACL:
		if ps.tokenPoliciesLRU != nil {
			ps.tokenPoliciesLRU.Remove(index)
		}

	default:
		return fmt.Errorf("unknown policy type: %w", err)
	}

	return nil
}

// SetPolicy is used to create or update the given policy
func (ps *Store) SetPolicy(ctx context.Context, p *Policy, casVersion *int) error {
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

func (ps *Store) setPolicyInternal(ctx context.Context, p *Policy, casVersion *int) error {
	defer ps.lockWithUnlock(ctx)()

	// Get the appropriate view based on policy type and namespace
	view := ps.getBarrierView(p.Namespace, p.Type)

	p.Modified = time.Now()

	existingEntry, err := view.Get(ctx, p.Name)
	if err != nil {
		return fmt.Errorf("unable to get existing policy for check-and-set: %w", err)
	}

	var existing Entry
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
	entry, err := logical.StorageEntryJSON(p.Name, &Entry{
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
	index := ps.cacheKey(p.Namespace, p.Name)

	switch p.Type {
	case TypeACL:
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
func (ps *Store) GetNonEGPPolicyType(ctx context.Context, name string) (*Type, error) {
	// We only support ACL policies at the moment.
	policy, err := ps.GetPolicy(ctx, name, TypeACL)
	if err != nil {
		return nil, err
	}

	if policy == nil {
		return nil, ErrPolicyNotExist
	}

	return &policy.Type, nil
}

// GetACLView returns the ACL view for the given namespace
func (ps *Store) GetACLView(ns *namespace.Namespace) barrier.View {
	return ps.core.NamespaceView(ns).SubView(barrier.SystemBarrierPrefix + ACLSubPath)
}

// getBarrierView returns the appropriate barrier view for the given namespace and policy type.
// Currently, this only supports ACL policies, so it delegates to getACLView.
func (ps *Store) getBarrierView(ns *namespace.Namespace, _ Type) barrier.View {
	return ps.GetACLView(ns)
}

// GetPolicy is used to fetch the named policy
func (ps *Store) GetPolicy(ctx context.Context, name string, policyType Type) (*Policy, error) {
	return ps.switchedGetPolicy(ctx, name, policyType, true)
}

func (ps *Store) switchedGetPolicy(ctx context.Context, name string, policyType Type, grabLock bool) (*Policy, error) {
	defer metrics.MeasureSince([]string{"policy", "get_policy"}, time.Now())

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	var cache *lru.TwoQueueCache[string, *Policy]
	var view barrier.View

	switch policyType {
	case TypeACL, TypeToken:
		cache = ps.tokenPoliciesLRU
		view = ps.GetACLView(ns)
		policyType = TypeACL
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
	if policyType == TypeACL && name == "root" {
		p := &Policy{
			Name:      "root",
			Namespace: ns,
			Type:      TypeACL,
		}
		if cache != nil {
			cache.Add(index, p)
		}
		return p, nil
	}

	if grabLock {
		defer ps.rLockWithUnlock(ctx)()
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

	policyEntry := new(Entry)
	pol := new(Policy)
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
	pol.Name = name
	pol.DataVersion = policyEntry.DataVersion
	pol.CASRequired = policyEntry.CASRequired
	pol.Raw = policyEntry.Raw
	pol.Type = policyEntry.Type
	pol.Templated = policyEntry.Templated
	pol.Expiration = policyEntry.Expiration
	pol.Modified = policyEntry.Modified
	pol.Namespace = ns
	switch policyEntry.Type {
	case TypeACL:
		// Parse normally
		p, err := ParseACLPolicy(ns, policyEntry.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy: %w", err)
		}
		pol.Paths = p.Paths

		// Reset this in case they set the name in the policy itself
		pol.Name = name
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyEntry.Type.String())
	}

	if cache != nil {
		// Update the LRU cache
		cache.Add(index, pol)
	}

	return pol, nil
}

// ListPolicies is used to list the available policies
func (ps *Store) ListPolicies(ctx context.Context, policyType Type, omitNonAssignable bool) ([]string, error) {
	return ps.ListPoliciesWithPrefix(ctx, policyType, "", omitNonAssignable)
}

// ListPoliciesWithPrefix is used to list policies with the given prefix in the specified namespace
// omitNonAssignable dictates whether result list
// should also contain the nonAssignable policies
func (ps *Store) ListPoliciesWithPrefix(ctx context.Context, policyType Type, prefix string, omitNonAssignable bool) ([]string, error) {
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
	case TypeACL:
		keys, err = logical.CollectKeysWithPrefix(ctx, view, prefix)
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyType)
	}

	if omitNonAssignable {
		keys = slices.DeleteFunc(keys, func(policyName string) bool {
			return slices.Contains(NonAssignablePolicies, policyName)
		})
	}

	return keys, err
}

// DeletePolicy is used to delete the named policy
func (ps *Store) DeletePolicy(ctx context.Context, name string, policyType Type) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, false)
}

// DeletePolicyForce is used to delete the named policy and force it even if
// default or a singleton. It's used for invalidations or namespace deletion
// where we internally need to actually remove a policy that the user normally
// isn't allowed to remove.
func (ps *Store) DeletePolicyForce(ctx context.Context, name string, policyType Type) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, true)
}

func (ps *Store) switchedDeletePolicy(ctx context.Context, name string, policyType Type, physicalDeletion, force bool) error {
	defer metrics.MeasureSince([]string{"policy", "delete_policy"}, time.Now())

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	// If not set, the call comes from invalidation, where we'll already have
	// grabbed the lock
	if physicalDeletion {
		defer ps.lockWithUnlock(ctx)()
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	view := ps.getBarrierView(ns, policyType)

	switch policyType {
	case TypeACL:
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
func (ps *Store) ACL(ctx context.Context, entity *identity.Entity, policyNames map[string][]string, additionalPolicies ...*Policy) (*ACL, error) {
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
			p, err := ps.GetPolicy(policyCtx, nsPolicyName, TypeToken)
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
	for i, pol := range allPolicies {
		if pol.Type == TypeACL && pol.Templated {
			if !fetchedGroups {
				fetchedGroups = true
				if entity != nil {
					directGroups, inheritedGroups, err := ps.core.IdentityStore().GroupsByEntityID(ctx, entity.ID)
					if err != nil {
						return nil, fmt.Errorf("failed to fetch group memberships: %w", err)
					}
					groups = append(directGroups, inheritedGroups...)
				}
			}
			p, err := ParseACLPolicyWithTemplating(pol.Namespace, pol.Raw, true, entity, groups)
			if err != nil {
				return nil, fmt.Errorf("error parsing templated policy %q: %w", pol.Name, err)
			}
			p.Name = pol.Name
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

// LoadACLPolicy is used to load default ACL policies in a specific
// namespace.
func (ps *Store) LoadACLPolicy(ctx context.Context, policyName, policyText string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Check if the pol already exists
	pol, err := ps.GetPolicy(ctx, policyName, TypeACL)
	if err != nil {
		return fmt.Errorf("error fetching %s policy from store: %w", policyName, err)
	}
	if pol != nil {
		if !slices.Contains(immutablePolicies, policyName) || policyText == pol.Raw {
			return nil
		}
	}

	pol, err = ParseACLPolicy(ns, policyText)
	if err != nil {
		return fmt.Errorf("error parsing %s policy: %w", policyName, err)
	}

	if pol == nil {
		return fmt.Errorf("parsing %q policy resulted in nil policy", policyName)
	}

	cas := &pol.DataVersion
	pol.Name = policyName
	pol.Type = TypeACL
	return ps.setPolicyInternal(ctx, pol, cas)
}

func (ps *Store) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (ps *Store) cacheKey(ns *namespace.Namespace, name string) string {
	return path.Join(ns.UUID, name)
}

// LoadDefaultPolicies loads default policies for the namespace in the provided context
func (ps *Store) LoadDefaultPolicies(ctx context.Context) error {
	// Load the default policy into the namespace
	if err := ps.LoadACLPolicy(ctx, defaultPolicyName, DefaultPolicy); err != nil {
		return fmt.Errorf("failed to load default policy: %w", err)
	}

	// Load the response wrapping policy into the namespace
	if err := ps.LoadACLPolicy(ctx, ResponseWrappingPolicyName, ResponseWrappingPolicy); err != nil {
		return fmt.Errorf("failed to load response wrapping policy: %w", err)
	}

	return nil
}

func (ps *Store) PurgeCache() {
	ps.tokenPoliciesLRU.Purge()
}
