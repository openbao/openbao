// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"sort"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type LockedUsersResponse struct {
	NamespaceID    string                    `json:"namespace_id" mapstructure:"namespace_id"`
	NamespacePath  string                    `json:"namespace_path" mapstructure:"namespace_path"`
	Counts         int                       `json:"counts" mapstructure:"counts"`
	MountAccessors []*ResponseMountAccessors `json:"mount_accessors" mapstructure:"mount_accessors"`
}

type ResponseMountAccessors struct {
	MountAccessor    string   `json:"mount_accessor" mapstructure:"mount_accessor"`
	Counts           int      `json:"counts" mapstructure:"counts"`
	AliasIdentifiers []string `json:"alias_identifiers" mapstructure:"alias_identifiers"`
}

// unlockUser deletes the entry for locked user from storage and userFailedLoginInfo map
func (b *SystemBackend) unlockUser(ctx context.Context, mountAccessor, aliasName string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// remove entry for locked user from storage
	// if read only error, the error is handled by handleError in logical_system.go
	// this will be forwarded to the active node
	view := NamespaceView(b.Core.barrier, ns).SubView(coreLockedUsersPath).SubView(mountAccessor + "/")
	if err := view.Delete(ctx, aliasName); err != nil {
		return err
	}

	loginUserInfoKey := FailedLoginUser{
		aliasName:     aliasName,
		mountAccessor: mountAccessor,
	}

	// remove entry for locked user from userFailedLoginInfo map and storage
	if err := b.Core.LocalUpdateUserFailedLoginInfo(ctx, loginUserInfoKey, nil, true); err != nil {
		return err
	}

	return nil
}

// handleLockedUsersQuery returns the locked user metrics
// by namespace in the decreasing order of locked users
func (b *SystemBackend) handleLockedUsersQuery(ctx context.Context, mountAccessor string) (map[string]interface{}, error) {
	// Calculate the namespace response breakdowns of locked users for query namespace and child namespaces (if needed)
	totalCount, byNamespaceResponse, err := b.getLockedUsersResponses(ctx, mountAccessor)
	if err != nil {
		return nil, err
	}

	// Now populate the response based on breakdowns.
	responseData := make(map[string]interface{})
	responseData["by_namespace"] = byNamespaceResponse
	responseData["total"] = totalCount
	return responseData, nil
}

// getLockedUsersResponses returns the locked users for a particular mount_accessor
// if provided in request otherwise returns locked users for the current namespace
// and all the child namespaces, entries are sorted in the decreasing count order
func (b *SystemBackend) getLockedUsersResponses(ctx context.Context, mountAccessor string) (int, []*LockedUsersResponse, error) {
	lockedUsersResponse := make([]*LockedUsersResponse, 0)
	totalCounts := 0

	queryNS, err := namespace.FromContext(ctx)
	if err != nil {
		return 0, nil, err
	}

	if mountAccessor != "" {
		// get the locked user response for mount_accessor provided with request
		view := NamespaceView(b.Core.barrier, queryNS).SubView(coreLockedUsersPath)
		totalCountForNS, mountAccessorsResponse, err := b.getMountAccessorsLockedUsers(ctx,
			view, mountAccessor+"/")
		if err != nil {
			return 0, nil, err
		}

		totalCounts += totalCountForNS
		lockedUsersResponse = append(lockedUsersResponse, &LockedUsersResponse{
			NamespaceID:    queryNS.ID,
			NamespacePath:  queryNS.Path,
			Counts:         totalCountForNS,
			MountAccessors: mountAccessorsResponse,
		})
		return totalCounts, lockedUsersResponse, nil
	}

	// no mount_accessor is provided in request, get information
	// for current namespace and all unsealed child namespaces
	nsList, err := b.Core.namespaceStore.ListAllNamespaces(ctx, true, false)
	if err != nil {
		return 0, nil, err
	}

	for _, ns := range nsList {
		// get mount accessors of locked users for this namespace
		view := NamespaceView(b.Core.barrier, ns).SubView(coreLockedUsersPath)
		mountAccessors, err := view.List(ctx, "")
		if err != nil {
			return 0, nil, err
		}

		// get the locked user response for mount_accessor list
		totalCountForNS, mountAccessorsResponse, err := b.getMountAccessorsLockedUsers(ctx, view, mountAccessors...)
		if err != nil {
			return 0, nil, err
		}

		totalCounts += totalCountForNS
		lockedUsersResponse = append(lockedUsersResponse, &LockedUsersResponse{
			NamespaceID:    ns.ID,
			NamespacePath:  ns.Path,
			Counts:         totalCountForNS,
			MountAccessors: mountAccessorsResponse,
		})
	}

	// sort namespaces in response by decreasing order of counts
	sort.Slice(lockedUsersResponse, func(i, j int) bool {
		return lockedUsersResponse[i].Counts > lockedUsersResponse[j].Counts
	})

	return totalCounts, lockedUsersResponse, nil
}

// getMountAccessorsLockedUsers returns the locked users for all the mountAccessors
// of locked users for a namespace. Result is sorted in the desc order of locked users.
func (b *SystemBackend) getMountAccessorsLockedUsers(ctx context.Context, view logical.Storage, mountAccessors ...string) (int, []*ResponseMountAccessors, error) {
	byMountAccessorsResponse := make([]*ResponseMountAccessors, 0)
	totalCountForMountAccessors := 0

	for _, mountAccessor := range mountAccessors {
		// get the list of aliases of locked users for a mount accessor
		aliasIdentifiers, err := view.List(ctx, mountAccessor)
		if err != nil {
			return 0, nil, err
		}

		totalCountForMountAccessors += len(aliasIdentifiers)
		byMountAccessorsResponse = append(byMountAccessorsResponse, &ResponseMountAccessors{
			MountAccessor:    strings.TrimSuffix(mountAccessor, "/"),
			Counts:           len(aliasIdentifiers),
			AliasIdentifiers: aliasIdentifiers,
		})

	}

	// sort mount Accessors in response by decreasing order of counts
	sort.Slice(byMountAccessorsResponse, func(i, j int) bool {
		return byMountAccessorsResponse[i].Counts > byMountAccessorsResponse[j].Counts
	})

	return totalCountForMountAccessors, byMountAccessorsResponse, nil
}
