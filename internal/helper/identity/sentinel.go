// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import "time"

func (e *Entity) SentinelGet(key string) (interface{}, error) {
	if e == nil {
		return nil, nil
	}
	switch key {
	case "aliases":
		return e.Aliases, nil
	case "id":
		return e.ID, nil
	case "meta", "metadata":
		return e.Metadata, nil
	case "name":
		return e.Name, nil
	case "creation_time":
		return e.CreationTime.AsTime().Format(time.RFC3339Nano), nil
	case "last_update_time":
		return e.LastUpdateTime.AsTime().Format(time.RFC3339Nano), nil
	case "merged_entity_ids":
		return e.MergedEntityIDs, nil
	case "policies":
		return e.Policies, nil
	}

	return nil, nil
}

func (e *Entity) SentinelKeys() []string {
	return []string{
		"id",
		"aliases",
		"metadata",
		"meta",
		"name",
		"creation_time",
		"last_update_time",
		"merged_entity_ids",
		"policies",
	}
}

func (p *Alias) SentinelGet(key string) (interface{}, error) {
	if p == nil {
		return nil, nil
	}
	switch key {
	case "id":
		return p.ID, nil
	case "mount_type":
		return p.MountType, nil
	case "mount_accessor":
		return p.MountAccessor, nil
	case "mount_path":
		return p.MountPath, nil
	case "meta", "metadata":
		return p.Metadata, nil
	case "name":
		return p.Name, nil
	case "creation_time":
		return p.CreationTime.AsTime().Format(time.RFC3339Nano), nil
	case "last_update_time":
		return p.LastUpdateTime.AsTime().Format(time.RFC3339Nano), nil
	case "merged_from_entity_ids":
		return p.MergedFromCanonicalIDs, nil
	}

	return nil, nil
}

func (a *Alias) SentinelKeys() []string {
	return []string{
		"id",
		"mount_type",
		"mount_accessor",
		"mount_path",
		"meta",
		"metadata",
		"name",
		"creation_time",
		"last_update_time",
		"merged_from_entity_ids",
	}
}

func (g *Group) SentinelGet(key string) (interface{}, error) {
	if g == nil {
		return nil, nil
	}
	switch key {
	case "id":
		return g.ID, nil
	case "name":
		return g.Name, nil
	case "policies":
		return g.Policies, nil
	case "parent_group_ids":
		return g.ParentGroupIDs, nil
	case "member_entity_ids":
		return g.MemberEntityIDs, nil
	case "meta", "metadata":
		return g.Metadata, nil
	case "creation_time":
		return g.CreationTime.AsTime().Format(time.RFC3339Nano), nil
	case "last_update_time":
		return g.LastUpdateTime.AsTime().Format(time.RFC3339Nano), nil
	}

	return nil, nil
}

func (g *Group) SentinelKeys() []string {
	return []string{
		"id",
		"name",
		"policies",
		"parent_group_ids",
		"member_entity_ids",
		"metadata",
		"meta",
		"creation_time",
		"last_update_time",
	}
}
