// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/hclutil"
	"github.com/openbao/openbao/sdk/v2/helper/identitytpl"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	DenyCapability   = "deny"
	CreateCapability = "create"
	ReadCapability   = "read"
	UpdateCapability = "update"
	DeleteCapability = "delete"
	ListCapability   = "list"
	SudoCapability   = "sudo"
	RootCapability   = "root"
	PatchCapability  = "patch"
	ScanCapability   = "scan"

	// Backwards compatibility
	OldDenyPathPolicy  = "deny"
	OldReadPathPolicy  = "read"
	OldWritePathPolicy = "write"
	OldSudoPathPolicy  = "sudo"
)

const (
	DenyCapabilityInt uint32 = 1 << iota
	CreateCapabilityInt
	ReadCapabilityInt
	UpdateCapabilityInt
	DeleteCapabilityInt
	ListCapabilityInt
	SudoCapabilityInt
	PatchCapabilityInt
	ScanCapabilityInt
)

// Currently only ACL policies are supported, with PolicyTypeToken being an
// alias for ACL policies. Support for RGP policies are Vault Enterprise only
// and thus aren't supported by OpenBao. In the future, PolicyStore may need
// to re-introduce support for the policyTypeMap, a cache which identifies
// what type of policy a PolicyTypeToken actually is, if we introduce a new
// policy type. However, if we do so, we should build the cache lazily,
// which both improves memory consumption with large number of policies and
// better supports namespace sealing.
type PolicyType uint32

const (
	PolicyTypeACL PolicyType = iota

	// Triggers a lookup in the map to figure out if ACL or RGP
	PolicyTypeToken PolicyType = iota + 2
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypeACL:
		return "acl"
	}

	return ""
}

var cap2Int = map[string]uint32{
	DenyCapability:   DenyCapabilityInt,
	CreateCapability: CreateCapabilityInt,
	ReadCapability:   ReadCapabilityInt,
	UpdateCapability: UpdateCapabilityInt,
	DeleteCapability: DeleteCapabilityInt,
	ListCapability:   ListCapabilityInt,
	SudoCapability:   SudoCapabilityInt,
	PatchCapability:  PatchCapabilityInt,
	ScanCapability:   ScanCapabilityInt,
}

// Policy is used to represent the policy specified by an ACL configuration.
type Policy struct {
	Name        string `hcl:"name"`
	DataVersion int
	CASRequired bool
	Paths       []*PathRules `hcl:"-"`
	Raw         string
	Type        PolicyType
	Templated   bool
	Expiration  time.Time
	Modified    time.Time
	namespace   *namespace.Namespace
}

// ShallowClone returns a shallow clone of the policy. This should not be used
// if any of the reference-typed fields are going to be modified
func (p *Policy) ShallowClone() *Policy {
	return &Policy{
		Name:        p.Name,
		DataVersion: p.DataVersion,
		CASRequired: p.CASRequired,
		Paths:       p.Paths,
		Raw:         p.Raw,
		Type:        p.Type,
		Templated:   p.Templated,
		namespace:   p.namespace,
	}
}

// PathRules represents a policy for a path in the namespace.
type PathRules struct {
	Path                string
	Policy              string
	Permissions         *ACLPermissions
	IsPrefix            bool
	HasSegmentWildcards bool
	Capabilities        []string

	ExpirationRaw string    `hcl:"expiration"`
	Expiration    time.Time `hcl:"-"`

	// These keys are used at the top level to make the HCL nicer; we store in
	// the ACLPermissions object though
	MinWrappingTTLHCL         interface{}              `hcl:"min_wrapping_ttl"`
	MaxWrappingTTLHCL         interface{}              `hcl:"max_wrapping_ttl"`
	AllowedParametersHCL      map[string][]interface{} `hcl:"allowed_parameters"`
	DeniedParametersHCL       map[string][]interface{} `hcl:"denied_parameters"`
	RequiredParametersHCL     []string                 `hcl:"required_parameters"`
	MFAMethodsHCL             []string                 `hcl:"mfa_methods"`
	PaginationLimitHCL        int                      `hcl:"pagination_limit"`
	ResponseKeysFilterPathHCL string                   `hcl:"list_scan_response_keys_filter_path"`
}

type IdentityFactor struct {
	GroupIDs          []string `hcl:"group_ids"`
	GroupNames        []string `hcl:"group_names"`
	ApprovalsRequired int      `hcl:"approvals"`
}

type ACLPermissions struct {
	CapabilitiesBitmap     uint32
	MinWrappingTTL         time.Duration
	MaxWrappingTTL         time.Duration
	AllowedParameters      map[string][]interface{}
	DeniedParameters       map[string][]interface{}
	RequiredParameters     []string
	MFAMethods             []string
	PaginationLimit        int
	GrantingPoliciesMap    map[uint32][]logical.PolicyInfo
	ResponseKeysFilterPath string
}

func (p *ACLPermissions) Clone() (*ACLPermissions, error) {
	ret := &ACLPermissions{
		CapabilitiesBitmap:     p.CapabilitiesBitmap,
		MinWrappingTTL:         p.MinWrappingTTL,
		MaxWrappingTTL:         p.MaxWrappingTTL,
		RequiredParameters:     p.RequiredParameters[:],
		PaginationLimit:        p.PaginationLimit,
		ResponseKeysFilterPath: p.ResponseKeysFilterPath,
	}

	switch {
	case p.AllowedParameters == nil:
	case len(p.AllowedParameters) == 0:
		ret.AllowedParameters = make(map[string][]interface{})
	default:
		clonedAllowed, err := copystructure.Copy(p.AllowedParameters)
		if err != nil {
			return nil, err
		}
		ret.AllowedParameters = clonedAllowed.(map[string][]interface{})
	}

	switch {
	case p.DeniedParameters == nil:
	case len(p.DeniedParameters) == 0:
		ret.DeniedParameters = make(map[string][]interface{})
	default:
		clonedDenied, err := copystructure.Copy(p.DeniedParameters)
		if err != nil {
			return nil, err
		}
		ret.DeniedParameters = clonedDenied.(map[string][]interface{})
	}

	switch {
	case p.MFAMethods == nil:
	case len(p.MFAMethods) == 0:
		ret.MFAMethods = []string{}
	default:
		clonedMFAMethods, err := copystructure.Copy(p.MFAMethods)
		if err != nil {
			return nil, err
		}
		ret.MFAMethods = clonedMFAMethods.([]string)
	}

	switch {
	case p.GrantingPoliciesMap == nil:
	case len(p.GrantingPoliciesMap) == 0:
		ret.GrantingPoliciesMap = make(map[uint32][]logical.PolicyInfo)
	default:
		clonedGrantingPoliciesMap, err := copystructure.Copy(p.GrantingPoliciesMap)
		if err != nil {
			return nil, err
		}
		ret.GrantingPoliciesMap = clonedGrantingPoliciesMap.(map[uint32][]logical.PolicyInfo)
	}

	return ret, nil
}

func addGrantingPoliciesToMap(m map[uint32][]logical.PolicyInfo, policy *Policy, capabilitiesBitmap uint32) map[uint32][]logical.PolicyInfo {
	if m == nil {
		m = make(map[uint32][]logical.PolicyInfo)
	}

	// For all possible policies, check if the provided capabilities include
	// them
	for _, capability := range cap2Int {
		if capabilitiesBitmap&capability == 0 {
			continue
		}

		m[capability] = append(m[capability], logical.PolicyInfo{
			Name:          policy.Name,
			NamespaceId:   policy.namespace.ID,
			NamespacePath: policy.namespace.Path,
			Type:          "acl",
		})
	}

	return m
}

// ParseACLPolicy is used to parse the specified ACL rules into an
// intermediary set of policies, before being compiled into
// the ACL
func ParseACLPolicy(ns *namespace.Namespace, rules string) (*Policy, error) {
	return parseACLPolicyWithTemplating(ns, rules, false, nil, nil)
}

// parseACLPolicyWithTemplating performs the actual work and checks whether we
// should perform substitutions. If performTemplating is true we know that it
// is templated so we don't check again, otherwise we check to see if it's a
// templated policy.
func parseACLPolicyWithTemplating(ns *namespace.Namespace, rules string, performTemplating bool, entity *identity.Entity, groups []*identity.Group) (*Policy, error) {
	// Parse the rules
	root, err := hcl.Parse(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Top-level item should be the object list
	list, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("failed to parse policy: does not contain a root object")
	}

	// Check for invalid top-level keys
	valid := []string{
		"name",
		"path",
	}
	if err := hclutil.CheckHCLKeys(list, valid); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Create the initial policy and store the raw text of the rules
	p := Policy{
		Raw:       rules,
		Type:      PolicyTypeACL,
		namespace: ns,
	}
	if err := hcl.DecodeObject(&p, list); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	if o := list.Filter("path"); len(o.Items) > 0 {
		if err := parsePaths(&p, o, performTemplating, entity, groups); err != nil {
			return nil, fmt.Errorf("failed to parse policy: %w", err)
		}
	}

	return &p, nil
}

func parsePaths(result *Policy, list *ast.ObjectList, performTemplating bool, entity *identity.Entity, groups []*identity.Group) error {
	paths := make([]*PathRules, 0, len(list.Items))
	for _, item := range list.Items {
		key := "path"
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		// Check the path
		if performTemplating {
			_, templated, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
				Mode:        identitytpl.ACLTemplating,
				String:      key,
				Entity:      identity.ToSDKEntity(entity),
				Groups:      identity.ToSDKGroups(groups),
				NamespaceID: result.namespace.ID,
			})
			if err != nil {
				continue
			}
			key = templated
		} else {
			hasTemplating, _, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
				Mode:              identitytpl.ACLTemplating,
				ValidityCheckOnly: true,
				String:            key,
			})
			if err != nil {
				return fmt.Errorf("failed to validate policy templating: %w", err)
			}
			if hasTemplating {
				result.Templated = true
			}
		}

		valid := []string{
			"comment",
			"policy",
			"capabilities",
			"allowed_parameters",
			"denied_parameters",
			"required_parameters",
			"min_wrapping_ttl",
			"max_wrapping_ttl",
			"mfa_methods",
			"pagination_limit",
			"expiration",
			"list_scan_response_keys_filter_path",
		}
		if err := hclutil.CheckHCLKeys(item.Val, valid); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("path %q:", key))
		}

		var pc PathRules

		// allocate memory so that DecodeObject can initialize the ACLPermissions struct
		pc.Permissions = new(ACLPermissions)

		pc.Path = key

		if err := hcl.DecodeObject(&pc, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("path %q:", key))
		}

		if len(pc.ExpirationRaw) > 0 {
			expiration, err := parseutil.ParseAbsoluteTime(pc.ExpirationRaw)
			if err != nil {
				return fmt.Errorf("path %q: invalid expiration time: %w", pc.Path, err)
			}

			pc.Expiration = expiration

			// If this path is expired, ignore it. We assume that the policy
			// author has set an overall expiration time of the last-valid
			// path for automatic cleanup.
			if time.Now().After(expiration) {
				// Skip the path because it has expired.
				continue
			}
		}

		// Strip a leading '/' as paths in Vault start after the / in the API path
		if len(pc.Path) > 0 && pc.Path[0] == '/' {
			pc.Path = pc.Path[1:]
		}

		// Ensure we are using the full request path internally
		pc.Path = result.namespace.Path + pc.Path

		if strings.Contains(pc.Path, "+*") {
			return fmt.Errorf("path %q: invalid use of wildcards ('+*' is forbidden)", pc.Path)
		}

		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}

		if strings.HasSuffix(pc.Path, "*") {
			// If there are segment wildcards, don't actually strip the
			// trailing asterisk, but don't want to hit the default case
			if !pc.HasSegmentWildcards {
				// Strip the glob character if found
				pc.Path = strings.TrimSuffix(pc.Path, "*")
				pc.IsPrefix = true
			}
		}

		// Map old-style policies into capabilities
		if len(pc.Policy) > 0 {
			switch pc.Policy {
			case OldDenyPathPolicy:
				pc.Capabilities = []string{DenyCapability}
			case OldReadPathPolicy:
				pc.Capabilities = append(pc.Capabilities, []string{ReadCapability, ListCapability}...)
			case OldWritePathPolicy:
				pc.Capabilities = append(pc.Capabilities, []string{CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability}...)
			case OldSudoPathPolicy:
				pc.Capabilities = append(pc.Capabilities, []string{CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability, SudoCapability}...)
			default:
				return fmt.Errorf("path %q: invalid policy %q", key, pc.Policy)
			}
		}

		// Initialize the map
		pc.Permissions.CapabilitiesBitmap = 0
		for _, cap := range pc.Capabilities {
			switch cap {
			// If it's deny, don't include any other capability
			case DenyCapability:
				pc.Capabilities = []string{DenyCapability}
				pc.Permissions.CapabilitiesBitmap = DenyCapabilityInt
				goto PathFinished
			case CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability, SudoCapability, PatchCapability, ScanCapability:
				pc.Permissions.CapabilitiesBitmap |= cap2Int[cap]
			default:
				return fmt.Errorf("path %q: invalid capability %q", key, cap)
			}
		}

		if pc.AllowedParametersHCL != nil {
			pc.Permissions.AllowedParameters = make(map[string][]interface{}, len(pc.AllowedParametersHCL))
			for k, v := range pc.AllowedParametersHCL {
				pc.Permissions.AllowedParameters[strings.ToLower(k)] = v
			}
		}
		if pc.DeniedParametersHCL != nil {
			pc.Permissions.DeniedParameters = make(map[string][]interface{}, len(pc.DeniedParametersHCL))

			for k, v := range pc.DeniedParametersHCL {
				pc.Permissions.DeniedParameters[strings.ToLower(k)] = v
			}
		}
		if pc.MinWrappingTTLHCL != nil {
			dur, err := parseutil.ParseDurationSecond(pc.MinWrappingTTLHCL)
			if err != nil {
				return fmt.Errorf("error parsing min_wrapping_ttl: %w", err)
			}
			pc.Permissions.MinWrappingTTL = dur
		}
		if pc.MaxWrappingTTLHCL != nil {
			dur, err := parseutil.ParseDurationSecond(pc.MaxWrappingTTLHCL)
			if err != nil {
				return fmt.Errorf("error parsing max_wrapping_ttl: %w", err)
			}
			pc.Permissions.MaxWrappingTTL = dur
		}
		if pc.MFAMethodsHCL != nil {
			pc.Permissions.MFAMethods = make([]string, len(pc.MFAMethodsHCL))
			copy(pc.Permissions.MFAMethods, pc.MFAMethodsHCL)
		}
		if pc.Permissions.MinWrappingTTL != 0 &&
			pc.Permissions.MaxWrappingTTL != 0 &&
			pc.Permissions.MaxWrappingTTL < pc.Permissions.MinWrappingTTL {
			return errors.New("max_wrapping_ttl cannot be less than min_wrapping_ttl")
		}
		if len(pc.RequiredParametersHCL) > 0 {
			pc.Permissions.RequiredParameters = pc.RequiredParametersHCL[:]
		}
		if len(pc.ResponseKeysFilterPathHCL) > 0 {
			pc.Permissions.ResponseKeysFilterPath = pc.ResponseKeysFilterPathHCL
			if (pc.Permissions.CapabilitiesBitmap & ListCapabilityInt) == 0 {
				return errors.New("list_scan_response_keys_filter_path needs to be used on a path with the list capability")
			}

			tmpl, err := compileTemplatePathForFiltering(pc.Permissions.ResponseKeysFilterPath)
			if err != nil {
				return fmt.Errorf("unable to compile template for list_scan_response_keys_filter_path: %w", err)
			}

			// Use a random string to validate that key was used.
			keyOne, err := base62.Random(32)
			if err != nil {
				return fmt.Errorf("failed to generate random string to validate policy: %w", err)
			}

			keyTwo, err := base62.Random(32)
			if err != nil {
				return fmt.Errorf("failed to generate random string to validate policy: %w", err)
			}

			checkPathOne, err := useTemplateForFiltering(tmpl, pc.Path, keyOne)
			if err != nil {
				return fmt.Errorf("failed to validate list_scan_response_keys_filter_path: %w", err)
			}

			checkPathTwo, err := useTemplateForFiltering(tmpl, pc.Path, keyTwo)
			if err != nil {
				return fmt.Errorf("failed to validate list_scan_response_keys_filter_path: %w", err)
			}

			if checkPathOne == checkPathTwo && keyOne != keyTwo {
				return fmt.Errorf("list_scan_response_keys_filter_path resulted in same path for two different keys")
			}
		}

		pc.Permissions.PaginationLimit = pc.PaginationLimitHCL
	PathFinished:
		paths = append(paths, &pc)
	}

	result.Paths = paths
	return nil
}
