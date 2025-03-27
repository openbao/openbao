// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestIdentityStore_Lookup_Entity(t *testing.T) {
	var err error
	var resp *logical.Response

	ctx := namespace.RootContext(nil)
	i, accessor, _ := testIdentityStoreWithAppRoleAuth(ctx, t)

	entityReq := &logical.Request{
		Path:      "entity",
		Operation: logical.UpdateOperation,
	}
	resp, err = i.HandleRequest(ctx, entityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}
	entityID := resp.Data["id"].(string)

	aliasReq := &logical.Request{
		Path:      "entity-alias",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"name":           "testaliasname",
			"mount_accessor": accessor,
			"entity_id":      entityID,
		},
	}

	resp, err = i.HandleRequest(ctx, aliasReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}
	aliasID := resp.Data["id"].(string)

	entity, err := i.MemDBEntityByID(entityID, false)
	if err != nil {
		t.Fatal(err)
	}

	lookupReq := &logical.Request{
		Path:      "lookup/entity",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"id": entityID,
		},
	}
	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}

	if resp.Data["id"].(string) != entityID {
		t.Fatalf("bad: entity: %#v", resp.Data)
	}

	lookupReq.Data = map[string]interface{}{
		"name": entity.Name,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}

	if resp.Data["id"].(string) != entityID {
		t.Fatalf("bad: entity: %#v", resp.Data)
	}

	lookupReq.Data = map[string]interface{}{
		"alias_id": aliasID,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}

	if resp.Data["id"].(string) != entityID {
		t.Fatalf("bad: entity: %#v", resp.Data)
	}

	lookupReq.Data = map[string]interface{}{
		"alias_name":           "testaliasname",
		"alias_mount_accessor": accessor,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}

	if resp.Data["id"].(string) != entityID {
		t.Fatalf("bad: entity: %#v", resp.Data)
	}

	// Supply 2 query criteria
	lookupReq.Data = map[string]interface{}{
		"id":   entityID,
		"name": entity.Name,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Supply alias name and skip accessor
	lookupReq.Data = map[string]interface{}{
		"alias_name": "testaliasname",
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Supply alias accessor and skip name
	lookupReq.Data = map[string]interface{}{
		"alias_mount_accessor": accessor,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Don't supply any criteria
	lookupReq.Data = nil

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Delete the alias in the entity
	aliasReq.Path = "entity-alias/id/" + aliasID
	aliasReq.Operation = logical.DeleteOperation
	resp, err = i.HandleRequest(ctx, aliasReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}

	lookupReq.Data = map[string]interface{}{
		"alias_id": aliasID,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %#v\nresp: %v", err, resp)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}
}

func TestIdentityStore_Lookup_Group(t *testing.T) {
	var err error
	var resp *logical.Response

	ctx := namespace.RootContext(nil)
	i, accessor, _ := testIdentityStoreWithAppRoleAuth(ctx, t)

	groupReq := &logical.Request{
		Path:      "group",
		Operation: logical.UpdateOperation,
	}
	resp, err = i.HandleRequest(ctx, groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	groupID := resp.Data["id"].(string)
	groupName := resp.Data["name"].(string)

	lookupReq := &logical.Request{
		Path:      "lookup/group",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"id": groupID,
		},
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	if resp.Data["id"].(string) != groupID {
		t.Fatal("failed to lookup group")
	}

	lookupReq.Data = map[string]interface{}{
		"name": groupName,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	if resp.Data["id"].(string) != groupID {
		t.Fatal("failed to lookup group")
	}

	// Query using an invalid alias_id
	lookupReq.Data = map[string]interface{}{
		"alias_id": "invalidaliasid",
	}
	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	groupReq.Data = map[string]interface{}{
		"type": "external",
	}
	resp, err = i.HandleRequest(ctx, groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	groupID = resp.Data["id"].(string)

	aliasReq := &logical.Request{
		Path:      "group-alias",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"canonical_id":   groupID,
			"name":           "testgroupalias",
			"mount_accessor": accessor,
		},
	}
	resp, err = i.HandleRequest(ctx, aliasReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	aliasID := resp.Data["id"].(string)

	lookupReq.Data = map[string]interface{}{
		"alias_id": aliasID,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	if resp.Data["id"].(string) != groupID {
		t.Fatal("failed to lookup group")
	}

	lookupReq.Data = map[string]interface{}{
		"alias_name":           "testgroupalias",
		"alias_mount_accessor": accessor,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %#v\n", resp, err)
	}
	if resp.Data["id"].(string) != groupID {
		t.Fatal("failed to lookup group")
	}

	// Supply 2 query criteria
	lookupReq.Data = map[string]interface{}{
		"id":   groupID,
		"name": groupName,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Supply alias name and skip accessor
	lookupReq.Data = map[string]interface{}{
		"alias_name": "testgroupalias",
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Supply alias accessor and skip name
	lookupReq.Data = map[string]interface{}{
		"alias_mount_accessor": accessor,
	}

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}

	// Don't supply any criteria
	lookupReq.Data = nil

	resp, err = i.HandleRequest(ctx, lookupReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error")
	}
}
