// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	//
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"

	//
	"github.com/tmccombs/hcl2json/convert"
)

// ExternalEvaluationRequestPolicy represents a policy inside the request sent to an external service for ACL evaluation
type ExternalEvaluationRequestPolicy struct {
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

// ExternalEvaluationRequest represents the request sent to an external service for ACL evaluation
type ExternalEvaluationRequest struct {
	Path      string                            `json:"path"`
	Operation string                            `json:"operation"`
	Policies  []ExternalEvaluationRequestPolicy `json:"policies"`

	// Useful payload
	Parameters map[string]any `json:"parameters"`
	TTL        time.Duration  `json:"TTL"`

	// Make it easy for fast responses
	IsRoot          bool `json:"isRoot"`
	IsAuthenticated bool `json:"isAuthenticated"`
}

// ExternalEvaluationResponse represents the response given by an external service evaluating ACL
type ExternalEvaluationResponse struct {
	Capabilities     []string `json:"capabilities"`
	GrantingPolicies []string `json:"grantingPolicies"`
}

// AllowOperationExternal is used to check if the given operation is permitted by asking an external authorization service.
func (a *ACL) AllowOperationExternal(ctx context.Context, req *logical.Request, capCheckOnly bool) (ret *ACLResults) {
	ret = new(ACLResults)

	// Fast-path root
	if a.root {
		ret.Allowed = true
		ret.RootPrivs = true
		ret.IsRoot = true
		ret.GrantingPolicies = []logical.PolicyInfo{{
			Name:          "root",
			NamespaceId:   "root",
			NamespacePath: "",
			Type:          "acl",
		}}
		return
	}
	op := req.Operation

	// Help is always allowed
	if op == logical.HelpOperation {
		ret.Allowed = true
		return
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return
	}
	path := ns.Path + req.Path

	// The request path should take care of this already but this is useful for
	// tests and as defense in depth
	for {
		if len(path) > 0 && path[0] == '/' {
			path = path[1:]
		} else {
			break
		}
	}

	//
	var reqTTL time.Duration
	wrapInfo := req.WrapInfo
	if wrapInfo != nil {
		reqTTL = wrapInfo.TTL
	}

	// Marshal policies into JSON for ease with the external service
	var rawAclPoliciesJson []ExternalEvaluationRequestPolicy
	for _, policy := range a.rawAclPolicies {

		jsonBytes, err := convert.Bytes([]byte(policy.Raw), "policy.hcl", convert.Options{})
		if err != nil {
			continue
		}

		tmpPolicy := ExternalEvaluationRequestPolicy{
			Name: policy.Name,
			Raw:  string(jsonBytes),
		}
		rawAclPoliciesJson = append(rawAclPoliciesJson, tmpPolicy)
	}

	reqContent := ExternalEvaluationRequest{
		Path:      path,
		Operation: string(op),
		Policies:  rawAclPoliciesJson,

		Parameters: req.Data,
		TTL:        reqTTL,

		IsRoot:          a.root,
		IsAuthenticated: req.Unauthenticated,
	}

	extReqContentBytes, err := json.Marshal(reqContent)
	if err != nil {
		return
	}

	extReq, err := http.NewRequest(http.MethodPost, a.externalAclAddress, bytes.NewReader(extReqContentBytes))
	if err != nil {
		return
	}

	extRes, err := http.DefaultClient.Do(extReq)
	if err != nil {
		return
	}

	extResBodyBytes, err := io.ReadAll(extRes.Body)
	if err != nil {
		return
	}

	resContent := ExternalEvaluationResponse{}
	err = json.Unmarshal(extResBodyBytes, &resContent)
	if err != nil {
		return
	}

	// Don't allow non-explicit capabilities
	if len(resContent.Capabilities) == 0 {
		return
	}

	// Throw info about policies causing the capabilities
	for _, grantingPolicy := range resContent.GrantingPolicies {
		tmpPolicy := logical.PolicyInfo{
			Name:          grantingPolicy,
			NamespaceId:   "root",
			NamespacePath: "",
			Type:          "acl",
		}
		ret.GrantingPolicies = append(ret.GrantingPolicies, tmpPolicy)
	}

	// Early deny when required
	if slices.Contains(resContent.Capabilities, DenyCapability) {
		ret.CapabilitiesBitmap |= DenyCapabilityInt
		return
	}

	// Add the rest of capabilities
	if slices.Contains(resContent.Capabilities, SudoCapability) {
		ret.RootPrivs = true
		ret.CapabilitiesBitmap |= SudoCapabilityInt
	}

	//
	ret.Allowed = slices.Contains(resContent.Capabilities, string(op))

	for _, capability := range resContent.Capabilities {

		switch logical.Operation(capability) {
		case logical.ReadOperation:
			ret.CapabilitiesBitmap |= ReadCapabilityInt
		case logical.ListOperation:
			ret.CapabilitiesBitmap |= ListCapabilityInt
		case logical.UpdateOperation:
			ret.CapabilitiesBitmap |= UpdateCapabilityInt
		case logical.DeleteOperation:
			ret.CapabilitiesBitmap |= DeleteCapabilityInt
		case logical.CreateOperation:
			ret.CapabilitiesBitmap |= CreateCapabilityInt
		case logical.PatchOperation:
			ret.CapabilitiesBitmap |= PatchCapabilityInt
		case logical.ScanOperation:
			ret.CapabilitiesBitmap |= ScanCapabilityInt

		// These three re-use UpdateCapabilityInt since that's the most appropriate
		// capability/operation mapping
		case logical.RevokeOperation, logical.RenewOperation, logical.RollbackOperation:
			ret.CapabilitiesBitmap |= UpdateCapabilityInt
		default:
			return
		}
	}

	return
}
