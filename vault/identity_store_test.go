// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/armon/go-metrics"
	"github.com/go-test/deep"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/audit"
	auditFile "github.com/openbao/openbao/builtin/audit/file"
	credAppRole "github.com/openbao/openbao/builtin/credential/approle"
	credUserpass "github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/storagepacker"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestIdentityStore_DeleteEntityAlias(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(nil)
	txn := c.identityStore.db(ctx).Txn(true)
	defer txn.Abort()

	alias := &identity.Alias{
		ID:             "testAliasID1",
		CanonicalID:    "testEntityID",
		MountType:      "testMountType",
		MountAccessor:  "testMountAccessor",
		Name:           "testAliasName",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("testEntityID"),
	}
	alias2 := &identity.Alias{
		ID:             "testAliasID2",
		CanonicalID:    "testEntityID",
		MountType:      "testMountType",
		MountAccessor:  "testMountAccessor2",
		Name:           "testAliasName2",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("testEntityID"),
	}
	entity := &identity.Entity{
		ID:       "testEntityID",
		Name:     "testEntityName",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias,
			alias2,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker(ctx).BucketKey("testEntityID"),
	}

	err := c.identityStore.upsertEntityInTxn(ctx, txn, entity, nil, false)
	require.NoError(t, err)

	err = c.identityStore.deleteAliasesInEntityInTxn(txn, entity, []*identity.Alias{alias, alias2})
	require.NoError(t, err)

	txn.Commit()

	alias, err = c.identityStore.MemDBAliasByID(ctx, "testAliasID1", false, false)
	require.NoError(t, err)
	require.Nil(t, alias)

	alias, err = c.identityStore.MemDBAliasByID(ctx, "testAliasID2", false, false)
	require.NoError(t, err)
	require.Nil(t, alias)

	entity, err = c.identityStore.MemDBEntityByID(ctx, "testEntityID", false)
	require.NoError(t, err)

	require.Len(t, entity.Aliases, 0)
}

func TestIdentityStore_UnsealingWhenConflictingAliasNames(t *testing.T) {
	err := AddTestCredentialBackend("approle", credAppRole.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ClearTestCredentialBackends()

	c, unsealKey, root := TestCoreUnsealed(t)
	ctx := namespace.RootContext(nil)

	meGH := &MountEntry{
		Table:       credentialTableType,
		Path:        "approle/",
		Type:        "approle",
		Description: "approle auth",
	}

	err = c.enableCredential(namespace.RootContext(nil), meGH)
	if err != nil {
		t.Fatal(err)
	}

	alias := &identity.Alias{
		ID:             "alias1",
		CanonicalID:    "entity1",
		MountType:      "approle",
		MountAccessor:  meGH.Accessor,
		Name:           "approleuser",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("entity1"),
	}
	entity := &identity.Entity{
		ID:       "entity1",
		Name:     "name1",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker(ctx).BucketKey("entity1"),
	}

	err = c.identityStore.upsertEntity(namespace.RootContext(nil), entity, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	alias2 := &identity.Alias{
		ID:             "alias2",
		CanonicalID:    "entity2",
		MountType:      "approle",
		MountAccessor:  meGH.Accessor,
		Name:           "APPROLEUSER",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("entity2"),
	}
	entity2 := &identity.Entity{
		ID:       "entity2",
		Name:     "name2",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias2,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker(ctx).BucketKey("entity2"),
	}

	// Persist the second entity directly without the regular flow. This will skip
	// merging of these enties.
	entity2Any, err := anypb.New(entity2)
	if err != nil {
		t.Fatal(err)
	}
	item := &storagepacker.Item{
		ID:      entity2.ID,
		Message: entity2Any,
	}

	if err = c.identityStore.entityPacker(ctx).PutItem(ctx, item); err != nil {
		t.Fatal(err)
	}

	// Seal and ensure that unseal works
	if err = c.Seal(root); err != nil {
		t.Fatal(err)
	}

	var unsealed bool
	for i := 0; i < 3; i++ {
		unsealed, err = c.Unseal(unsealKey[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	if !unsealed {
		t.Fatal("still sealed")
	}
}

func TestIdentityStore_EntityIDPassthrough(t *testing.T) {
	// Enable AppRole auth and initialize
	ctx := namespace.RootContext(nil)
	is, approleAccessor, core := testIdentityStoreWithAppRoleAuth(ctx, t)
	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: approleAccessor,
		Name:          "approleuser",
	}

	// Create an entity with AppRole alias
	entity, _, err := is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}

	// Create a token with the above created entity set on it
	ent := &logical.TokenEntry{
		ID:           "testtokenid",
		Path:         "test",
		Policies:     []string{"root"},
		CreationTime: time.Now().Unix(),
		EntityID:     entity.ID,
		NamespaceID:  namespace.RootNamespaceID,
	}
	if err := core.tokenStore.create(ctx, ent, true); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Set a request handler to the noop backend which responds with the entity
	// ID received in the request object
	requestHandler := func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
		return &logical.Response{
			Data: map[string]interface{}{
				"entity_id": req.EntityID,
			},
		}, nil
	}

	noop := &NoopBackend{
		RequestHandler: requestHandler,
	}

	// Mount the noop backend
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "logical/")
	meUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	err = core.router.Mount(noop, "test/backend/", &MountEntry{Path: "test/backend/", Type: "noop", UUID: meUUID, Accessor: "noop-accessor", namespace: namespace.RootNamespace}, view)
	if err != nil {
		t.Fatal(err)
	}

	// Make the request with the above created token
	resp, err := core.HandleRequest(ctx, &logical.Request{
		ClientToken: "testtokenid",
		Operation:   logical.ReadOperation,
		Path:        "test/backend/foo",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\n err: %v", resp, err)
	}

	// Expected entity ID to be in the response
	if resp.Data["entity_id"] != entity.ID {
		t.Fatal("expected entity ID to be passed through to the backend")
	}
}

func TestIdentityStore_CreateOrFetchEntity(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	is, approleAccessor, upAccessor, core := testIdentityStoreWithAppRoleUserpassAuth(ctx, t, false)
	testIdentityStoreCreateOrFetchEntity(t, ctx, is, approleAccessor, upAccessor, core)
}

func TestIdentityStore_CreateOrFetchEntity_UnsafeShared(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	is, approleAccessor, upAccessor, core := testIdentityStoreWithAppRoleUserpassAuth(ctx, t, true)
	testIdentityStoreCreateOrFetchEntity(t, ctx, is, approleAccessor, upAccessor, core)
}

func testIdentityStoreCreateOrFetchEntity(t *testing.T, ctx context.Context, is *IdentityStore, approleAccessor string, upAccessor string, core *Core) {
	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: approleAccessor,
		Name:          "approleuser",
		Metadata: map[string]string{
			"foo": "a",
		},
	}

	entity, _, err := is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}

	if len(entity.Aliases) != 1 {
		t.Fatalf("bad: length of aliases; expected: 1, actual: %d", len(entity.Aliases))
	}

	if entity.Aliases[0].Name != alias.Name {
		t.Fatalf("bad: alias name; expected: %q, actual: %q", alias.Name, entity.Aliases[0].Name)
	}

	entity, _, err = is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}

	if len(entity.Aliases) != 1 {
		t.Fatalf("bad: length of aliases; expected: 1, actual: %d", len(entity.Aliases))
	}

	if entity.Aliases[0].Name != alias.Name {
		t.Fatalf("bad: alias name; expected: %q, actual: %q", alias.Name, entity.Aliases[0].Name)
	}
	if diff := deep.Equal(entity.Aliases[0].Metadata, map[string]string{"foo": "a"}); diff != nil {
		t.Fatal(diff)
	}

	// Add a new alias to the entity and verify its existence
	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity-alias",
		Data: map[string]interface{}{
			"name":           "approleuser2",
			"canonical_id":   entity.ID,
			"mount_accessor": upAccessor,
		},
	}

	resp, err := is.HandleRequest(ctx, registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	entity, _, err = is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}

	if len(entity.Aliases) != 2 {
		t.Fatalf("bad: length of aliases; expected: 2, actual: %d", len(entity.Aliases))
	}

	if entity.Aliases[1].Name != "approleuser2" {
		t.Fatalf("bad: alias name; expected: %q, actual: %q", alias.Name, "approleuser2")
	}

	if diff := deep.Equal(entity.Aliases[1].Metadata, map[string]string(nil)); diff != nil {
		t.Fatal(diff)
	}

	// Change the metadata of an existing alias and verify that
	// a the change takes effect only for the target alias.
	alias.Metadata = map[string]string{
		"foo": "zzzz",
	}

	entity, _, err = is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}

	if len(entity.Aliases) != 2 {
		t.Fatalf("bad: length of aliases; expected: 2, actual: %d", len(entity.Aliases))
	}

	if diff := deep.Equal(entity.Aliases[0].Metadata, map[string]string{"foo": "zzzz"}); diff != nil {
		t.Fatal(diff)
	}

	if diff := deep.Equal(entity.Aliases[1].Metadata, map[string]string(nil)); diff != nil {
		t.Fatal(diff)
	}
}

func TestIdentityStore_EntityByAliasFactors(t *testing.T) {
	var err error
	var resp *logical.Response

	ctx := namespace.RootContext(nil)
	is, approleAccessor, _ := testIdentityStoreWithAppRoleAuth(ctx, t)

	registerData := map[string]interface{}{
		"name":     "testentityname",
		"metadata": []string{"someusefulkey=someusefulvalue"},
		"policies": []string{"testpolicy1", "testpolicy2"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register the entity
	resp, err = is.HandleRequest(ctx, registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatal("entity id not present in response")
	}
	entityID := idRaw.(string)
	if entityID == "" {
		t.Fatal("invalid entity id")
	}

	aliasData := map[string]interface{}{
		"entity_id":      entityID,
		"name":           "alias_name",
		"mount_accessor": approleAccessor,
	}
	aliasReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "alias",
		Data:      aliasData,
	}

	resp, err = is.HandleRequest(ctx, aliasReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected a non-nil response")
	}

	entity, err := is.entityByAliasFactors(ctx, approleAccessor, "alias_name", false)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}
	if entity.ID != entityID {
		t.Fatalf("bad: entity ID; expected: %q actual: %q", entityID, entity.ID)
	}
	if entity.NamespaceID != namespace.RootNamespaceID {
		t.Fatalf("bad: entity namespace ID; expected: %q actual: %q", namespace.RootNamespaceID, entity.NamespaceID)
	}
}

func TestIdentityStore_WrapInfoInheritance(t *testing.T) {
	var err error
	var resp *logical.Response

	ctx := namespace.RootContext(nil)
	core, is, ts, _ := testCoreWithIdentityTokenAppRole(ctx, t)

	registerData := map[string]interface{}{
		"name":     "testentityname",
		"metadata": []string{"someusefulkey=someusefulvalue"},
		"policies": []string{"testpolicy1", "testpolicy2"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register the entity
	resp, err = is.HandleRequest(ctx, registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatal("entity id not present in response")
	}
	entityID := idRaw.(string)
	if entityID == "" {
		t.Fatal("invalid entity id")
	}

	// Create a token which has EntityID set and has update permissions to
	// sys/wrapping/wrap
	te := &logical.TokenEntry{
		Path:     "test",
		Policies: []string{"default", responseWrappingPolicyName},
		EntityID: entityID,
		TTL:      time.Hour,
	}
	testMakeTokenDirectly(t, ctx, ts, te)

	wrapReq := &logical.Request{
		Path:        "sys/wrapping/wrap",
		ClientToken: te.ID,
		Operation:   logical.UpdateOperation,
		Data: map[string]interface{}{
			"foo": "bar",
		},
		WrapInfo: &logical.RequestWrapInfo{
			TTL: time.Duration(5 * time.Second),
		},
	}

	resp, err = core.HandleRequest(ctx, wrapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v, err: %v", resp, err)
	}

	if resp.WrapInfo == nil {
		t.Fatal("expected a non-nil WrapInfo")
	}

	if resp.WrapInfo.WrappedEntityID != entityID {
		t.Fatalf("bad: WrapInfo in response not having proper entity ID set; expected: %q, actual:%q", entityID, resp.WrapInfo.WrappedEntityID)
	}
}

func TestIdentityStore_TokenEntityInheritance(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ts := c.tokenStore

	// Create a token which has EntityID set
	te := &logical.TokenEntry{
		Path:     "test",
		Policies: []string{"dev", "prod"},
		EntityID: "testentityid",
		TTL:      time.Hour,
	}
	ctx := namespace.RootContext(nil)
	testMakeTokenDirectly(t, ctx, ts, te)

	// Create a child token; this should inherit the EntityID
	tokenReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "create",
		ClientToken: te.ID,
	}

	resp, err := ts.HandleRequest(ctx, tokenReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v err: %v", err, resp)
	}

	if resp.Auth.EntityID != te.EntityID {
		t.Fatalf("bad: entity ID; expected: %v, actual: %v", te.EntityID, resp.Auth.EntityID)
	}

	// Create an orphan token; this should not inherit the EntityID
	tokenReq.Path = "create-orphan"
	resp, err = ts.HandleRequest(ctx, tokenReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v err: %v", err, resp)
	}

	if resp.Auth.EntityID != "" {
		t.Fatal("expected entity ID to be not set")
	}
}

func TestIdentityStore_MergeConflictingAliases(t *testing.T) {
	err := AddTestCredentialBackend("approle", credAppRole.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ClearTestCredentialBackends()

	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(nil)

	meGH := &MountEntry{
		Table:       credentialTableType,
		Path:        "approle/",
		Type:        "approle",
		Description: "approle auth",
	}

	err = c.enableCredential(namespace.RootContext(nil), meGH)
	if err != nil {
		t.Fatal(err)
	}

	alias := &identity.Alias{
		ID:             "alias1",
		CanonicalID:    "entity1",
		MountType:      "approle",
		MountAccessor:  meGH.Accessor,
		Name:           "approleuser",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("entity1"),
	}
	entity := &identity.Entity{
		ID:       "entity1",
		Name:     "name1",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker(ctx).BucketKey("entity1"),
	}
	err = c.identityStore.upsertEntity(namespace.RootContext(nil), entity, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	alias2 := &identity.Alias{
		ID:             "alias2",
		CanonicalID:    "entity2",
		MountType:      "approle",
		MountAccessor:  meGH.Accessor,
		Name:           "approleuser",
		LocalBucketKey: c.identityStore.localAliasPacker(ctx).BucketKey("entity2"),
	}
	entity2 := &identity.Entity{
		ID:       "entity2",
		Name:     "name2",
		Policies: []string{"bar", "baz"},
		Aliases: []*identity.Alias{
			alias2,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker(ctx).BucketKey("entity2"),
	}

	err = c.identityStore.upsertEntity(namespace.RootContext(nil), entity2, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	newEntity, _, err := c.identityStore.CreateOrFetchEntity(namespace.RootContext(nil), &logical.Alias{
		MountAccessor: meGH.Accessor,
		MountType:     "approle",
		Name:          "approleuser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if newEntity == nil {
		t.Fatal("nil new entity")
	}

	entityToUse := "entity1"
	if newEntity.ID == "entity1" {
		entityToUse = "entity2"
	}
	if len(newEntity.MergedEntityIDs) != 1 || newEntity.MergedEntityIDs[0] != entityToUse {
		t.Fatalf("bad merged entity ids: %v", newEntity.MergedEntityIDs)
	}
	if diff := deep.Equal(newEntity.Policies, []string{"bar", "baz", "foo"}); diff != nil {
		t.Fatal(diff)
	}

	newEntity, err = c.identityStore.MemDBEntityByID(ctx, entityToUse, false)
	if err != nil {
		t.Fatal(err)
	}
	if newEntity != nil {
		t.Fatal("got a non-nil entity")
	}
}

func testCoreWithIdentityTokenAppRole(ctx context.Context, t *testing.T) (*Core, *IdentityStore, *TokenStore, string) {
	is, approleAccessor, core := testIdentityStoreWithAppRoleAuth(ctx, t)
	return core, is, core.tokenStore, approleAccessor
}

func testIdentityStoreWithAppRoleAuth(ctx context.Context, t *testing.T) (*IdentityStore, string, *Core) {
	is, ghA, c, _ := testIdentityStoreWithAppRoleAuthRoot(ctx, t)
	return is, ghA, c
}

// testIdentityStoreWithAppRoleAuthRoot returns an instance of identity store
// which is mounted by default. This function also enables the approle auth
// backend to assist with testing aliases and entities that require an valid
// mount accessor of an auth backend.
func testIdentityStoreWithAppRoleAuthRoot(ctx context.Context, t *testing.T) (*IdentityStore, string, *Core, string) {
	// Add github credential factory to core config
	err := AddTestCredentialBackend("approle", credAppRole.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	defer ClearTestCredentialBackends()

	c, _, root := TestCoreUnsealed(t)

	meGH := &MountEntry{
		Table:       credentialTableType,
		Path:        "approle/",
		Type:        "approle",
		Description: "approle auth",
	}

	err = c.enableCredential(ctx, meGH)
	if err != nil {
		t.Fatal(err)
	}

	return c.identityStore, meGH.Accessor, c, root
}

func testIdentityStoreWithAppRoleUserpassAuth(ctx context.Context, t *testing.T, unsafeShared bool) (*IdentityStore, string, string, *Core) {
	// Setup 2 auth backends, github and userpass
	err := AddTestCredentialBackend("approle", credAppRole.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	err = AddTestCredentialBackend("userpass", credUserpass.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	defer ClearTestCredentialBackends()

	conf := &CoreConfig{
		BuiltinRegistry:              corehelpers.NewMockBuiltinRegistry(),
		UnsafeCrossNamespaceIdentity: unsafeShared,
		AuditBackends: map[string]audit.Factory{
			"file": auditFile.Factory,
		},
	}
	c, _, _ := TestCoreUnsealedWithConfig(t, conf)

	githubMe := &MountEntry{
		Table:       credentialTableType,
		Path:        "approle/",
		Type:        "approle",
		Description: "approle auth",
	}

	err = c.enableCredential(ctx, githubMe)
	if err != nil {
		t.Fatal(err)
	}

	userpassMe := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass",
	}

	err = c.enableCredential(ctx, userpassMe)
	if err != nil {
		t.Fatal(err)
	}

	return c.identityStore, githubMe.Accessor, userpassMe.Accessor, c
}

func TestIdentityStore_MetadataKeyRegex(t *testing.T) {
	key := "validVALID012_-=+/"

	if !metaKeyFormatRegEx(key) {
		t.Fatal("failed to accept valid metadata key")
	}

	key = "a:b"
	if metaKeyFormatRegEx(key) {
		t.Fatal("accepted invalid metadata key")
	}
}

func expectSingleCount(t *testing.T, sink *metrics.InmemSink, keyPrefix string) {
	t.Helper()

	intervals := sink.Data()
	// Test crossed an interval boundary, don't try to deal with it.
	if len(intervals) > 1 {
		t.Skip("Detected interval crossing.")
	}

	var counter *metrics.SampledValue = nil

	for _, c := range intervals[0].Counters {
		if strings.HasPrefix(c.Name, keyPrefix) {
			counter = &c
			break
		}
	}
	if counter == nil {
		t.Fatalf("No %q counter found.", keyPrefix)
	}

	if counter.Count != 1 {
		t.Errorf("Counter number of samples %v is not 1.", counter.Count)
	}

	if counter.Sum != 1.0 {
		t.Errorf("Counter sum %v is not 1.", counter.Sum)
	}
}

func TestIdentityStore_NewEntityCounter(t *testing.T) {
	// Add github credential factory to core config
	err := AddTestCredentialBackend("approle", credAppRole.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ClearTestCredentialBackends()

	c, _, _, sink := TestCoreUnsealedWithMetrics(t)

	meGH := &MountEntry{
		Table:       credentialTableType,
		Path:        "approle/",
		Type:        "approle",
		Description: "approle auth",
	}

	ctx := namespace.RootContext(nil)
	err = c.enableCredential(ctx, meGH)
	if err != nil {
		t.Fatal(err)
	}

	is := c.identityStore
	approleAccessor := meGH.Accessor

	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: approleAccessor,
		Name:          "approleuser",
		Metadata: map[string]string{
			"foo": "a",
		},
	}

	_, _, err = is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}

	expectSingleCount(t, sink, "identity.entity.creation")

	_, _, err = is.CreateOrFetchEntity(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}

	expectSingleCount(t, sink, "identity.entity.creation")
}

func TestIdentityStore_UpdateAliasMetadataPerAccessor(t *testing.T) {
	entity := &identity.Entity{
		ID:       "testEntityID",
		Name:     "testEntityName",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			{
				ID:            "testAliasID1",
				CanonicalID:   "testEntityID",
				MountType:     "testMountType",
				MountAccessor: "testMountAccessor",
				Name:          "sameAliasName",
			},
			{
				ID:            "testAliasID2",
				CanonicalID:   "testEntityID",
				MountType:     "testMountType",
				MountAccessor: "testMountAccessor2",
				Name:          "sameAliasName",
			},
		},
		NamespaceID: namespace.RootNamespaceID,
	}

	login := &logical.Alias{
		MountType:     "testMountType",
		MountAccessor: "testMountAccessor",
		Name:          "sameAliasName",
		ID:            "testAliasID",
		Metadata:      map[string]string{"foo": "bar"},
	}

	if i := changedAliasIndex(entity, login); i != 0 {
		t.Fatalf("wrong alias index changed. Expected 0, got %d", i)
	}

	login2 := &logical.Alias{
		MountType:     "testMountType",
		MountAccessor: "testMountAccessor2",
		Name:          "sameAliasName",
		ID:            "testAliasID2",
		Metadata:      map[string]string{"bar": "foo"},
	}

	if i := changedAliasIndex(entity, login2); i != 1 {
		t.Fatalf("wrong alias index changed. Expected 1, got %d", i)
	}
}

// TestIdentityStore_DeleteCaseSensitivityKey tests that
// casesensitivity key gets removed from storage if it exists upon
// initializing identity store.
func TestIdentityStore_DeleteCaseSensitivityKey(t *testing.T) {
	c, unsealKey, root := TestCoreUnsealed(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// add caseSensitivityKey to storage
	entry, err := logical.StorageEntryJSON(caseSensitivityKey, &casesensitivity{
		DisableLowerCasedNames: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.identityStore.view(ctx).Put(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}

	// check if the value is stored in storage
	storageEntry, err := c.identityStore.view(ctx).Get(ctx, caseSensitivityKey)
	if err != nil {
		t.Fatal(err)
	}

	if storageEntry == nil {
		t.Fatal("bad: expected a non-nil entry for casesensitivity key")
	}

	// Seal and unseal to trigger identityStore initialize
	if err = c.Seal(root); err != nil {
		t.Fatal(err)
	}

	var unsealed bool
	for i := 0; i < len(unsealKey); i++ {
		unsealed, err = c.Unseal(unsealKey[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	if !unsealed {
		t.Fatal("still sealed")
	}

	// check if caseSensitivityKey exists after initialize
	storageEntry, err = c.identityStore.view(ctx).Get(ctx, caseSensitivityKey)
	if err != nil {
		t.Fatal(err)
	}

	if storageEntry != nil {
		t.Fatal("bad: expected no entry for casesensitivity key")
	}
}

func TestIdentityStore_NamespaceIsolation(t *testing.T) {
	// Register the userpass auth method
	err := AddTestCredentialBackend("userpass", credUserpass.Factory)
	require.NoError(t, err)
	defer ClearTestCredentialBackends()

	// Setup core and namespaces
	c, _, _ := TestCoreUnsealed(t)
	is := c.identityStore
	rootCtx := namespace.RootContext(context.Background())
	ns1, ns2 := setupNamespaces(t, c, rootCtx)

	// Create namespace contexts
	ns1Ctx := namespace.ContextWithNamespace(context.Background(), ns1)
	ns2Ctx := namespace.ContextWithNamespace(context.Background(), ns2)

	// Enable userpass auth in root namespace
	rootMount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in root",
	}
	err = c.enableCredential(rootCtx, rootMount)
	require.NoError(t, err)
	rootAccessor := rootMount.Accessor

	// Enable userpass auth in namespace 1
	ns1Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns1",
	}
	err = c.enableCredential(ns1Ctx, ns1Mount)
	require.NoError(t, err)
	ns1Accessor := ns1Mount.Accessor

	// Enable userpass auth in namespace 2
	ns2Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns2",
	}
	err = c.enableCredential(ns2Ctx, ns2Mount)
	require.NoError(t, err)
	ns2Accessor := ns2Mount.Accessor

	// Test entity creation in different namespaces
	t.Run("entity_creation_in_namespaces", func(t *testing.T) {
		// Test cases for different namespaces
		testCases := []struct {
			name        string
			ctx         context.Context
			expectedNS  string
			accessor    string
			description string
		}{
			{
				name:        "root-namespace",
				ctx:         rootCtx,
				expectedNS:  namespace.RootNamespaceID,
				accessor:    rootAccessor,
				description: "Entity creation in root namespace",
			},
			{
				name:        "namespace1",
				ctx:         ns1Ctx,
				expectedNS:  ns1.ID,
				accessor:    ns1Accessor,
				description: "Entity creation in namespace 1",
			},
			{
				name:        "namespace2",
				ctx:         ns2Ctx,
				expectedNS:  ns2.ID,
				accessor:    ns2Accessor,
				description: "Entity creation in namespace 2",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create a unique user for this test case
				userName := fmt.Sprintf("user-%s", tc.name)

				// Create an entity with alias
				alias := &logical.Alias{
					Name:          userName,
					MountAccessor: tc.accessor,
					MountType:     "userpass",
				}

				entity, _, err := is.CreateOrFetchEntity(tc.ctx, alias)
				require.NoError(t, err, tc.description)
				assert.Equal(t, tc.expectedNS, entity.NamespaceID, "Entity namespace ID should match context namespace")

				// Verify the alias is also in the correct namespace
				require.Len(t, entity.Aliases, 1, "Entity should have one alias")
				assert.Equal(t, tc.expectedNS, entity.Aliases[0].NamespaceID, "Alias namespace ID should match context namespace")
				assert.Equal(t, tc.accessor, entity.Aliases[0].MountAccessor, "Alias should have correct mount accessor")
			})
		}
	})

	// Test alias creation with the same username in different namespaces
	t.Run("same_username_different_namespaces", func(t *testing.T) {
		// Create entities with aliases having the same name across namespaces
		commonUserName := "common-user"

		// Create in root namespace
		rootAlias := &logical.Alias{
			Name:          commonUserName,
			MountAccessor: rootAccessor,
			MountType:     "userpass",
		}
		rootEntity, _, err := is.CreateOrFetchEntity(rootCtx, rootAlias)
		require.NoError(t, err)
		require.Equal(t, namespace.RootNamespaceID, rootEntity.NamespaceID)

		// Create in namespace 1
		ns1Alias := &logical.Alias{
			Name:          commonUserName,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}
		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)
		require.Equal(t, ns1.ID, ns1Entity.NamespaceID)

		// Create in namespace 2
		ns2Alias := &logical.Alias{
			Name:          commonUserName,
			MountAccessor: ns2Accessor,
			MountType:     "userpass",
		}
		ns2Entity, _, err := is.CreateOrFetchEntity(ns2Ctx, ns2Alias)
		require.NoError(t, err)
		require.Equal(t, ns2.ID, ns2Entity.NamespaceID)

		// Verify all three entities are different despite having same alias name
		require.NotEqual(t, rootEntity.ID, ns1Entity.ID, "Root and NS1 entities should be different")
		require.NotEqual(t, rootEntity.ID, ns2Entity.ID, "Root and NS2 entities should be different")
		require.NotEqual(t, ns1Entity.ID, ns2Entity.ID, "NS1 and NS2 entities should be different")

		// Verify entity lookup by alias works correctly in each namespace
		fetchedRoot, err := is.entityByAliasFactors(rootCtx, rootAccessor, commonUserName, false)
		require.NoError(t, err)
		require.NotNil(t, fetchedRoot)
		require.Equal(t, rootEntity.ID, fetchedRoot.ID)

		fetchedNS1, err := is.entityByAliasFactors(ns1Ctx, ns1Accessor, commonUserName, false)
		require.NoError(t, err)
		require.NotNil(t, fetchedNS1)
		require.Equal(t, ns1Entity.ID, fetchedNS1.ID)

		fetchedNS2, err := is.entityByAliasFactors(ns2Ctx, ns2Accessor, commonUserName, false)
		require.NoError(t, err)
		require.NotNil(t, fetchedNS2)
		require.Equal(t, ns2Entity.ID, fetchedNS2.ID)
	})

	// Test cross-namespace lookups
	t.Run("cross_namespace_lookups", func(t *testing.T) {
		userName := "cross-lookup-user"

		// Create entities in each namespace
		rootAlias := &logical.Alias{
			Name:          userName,
			MountAccessor: rootAccessor,
			MountType:     "userpass",
		}
		rootEntity, _, err := is.CreateOrFetchEntity(rootCtx, rootAlias)
		require.NoError(t, err)

		ns1Alias := &logical.Alias{
			Name:          userName,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}
		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)

		// Verify entities have aliases
		require.Len(t, rootEntity.Aliases, 1, "Root entity should have 1 alias")
		require.Len(t, ns1Entity.Aliases, 1, "NS1 entity should have 1 alias")

		// Cross-namespace lookups should return nil, not error
		crossEntity, err := is.entityByAliasFactors(rootCtx, ns1Accessor, userName, false)
		require.NoError(t, err)
		require.Nil(t, crossEntity, "Should not find NS1 entity from root context")

		crossEntity, err = is.entityByAliasFactors(ns1Ctx, rootAccessor, userName, false)
		require.NoError(t, err)
		require.Nil(t, crossEntity, "Should not find root entity from NS1 context")

		// Test looking up by ID directly - this should be namespace-aware
		fetchedRootEntity, err := is.MemDBEntityByID(rootCtx, rootEntity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, fetchedRootEntity, "Should be able to fetch root entity by ID")

		fetchedNS1Entity, err := is.MemDBEntityByID(ns1Ctx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, fetchedNS1Entity, "Should be able to fetch NS1 entity by ID")
	})

	// Test updating alias metadata in namespace-specific ways
	t.Run("update_alias_metadata_per_namespace", func(t *testing.T) {
		// Create aliases with initial metadata
		metadataUser := "metadata-user"

		rootAlias := &logical.Alias{
			Name:          metadataUser,
			MountAccessor: rootAccessor,
			MountType:     "userpass",
			Metadata: map[string]string{
				"initial": "root-value",
			},
		}

		ns1Alias := &logical.Alias{
			Name:          metadataUser,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
			Metadata: map[string]string{
				"initial": "ns1-value",
			},
		}

		rootEntity, _, err := is.CreateOrFetchEntity(rootCtx, rootAlias)
		require.NoError(t, err)

		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)

		// Update metadata in root namespace
		rootAlias.Metadata = map[string]string{
			"initial": "root-updated",
			"added":   "root-new",
		}

		updatedRootEntity, _, err := is.CreateOrFetchEntity(rootCtx, rootAlias)
		require.NoError(t, err)
		require.Equal(t, rootEntity.ID, updatedRootEntity.ID)
		require.Equal(t, "root-updated", updatedRootEntity.Aliases[0].Metadata["initial"])
		require.Equal(t, "root-new", updatedRootEntity.Aliases[0].Metadata["added"])

		// Update metadata in ns1 namespace
		ns1Alias.Metadata = map[string]string{
			"initial": "ns1-updated",
			"added":   "ns1-new",
		}

		updatedNs1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)
		require.Equal(t, ns1Entity.ID, updatedNs1Entity.ID)
		require.Equal(t, "ns1-updated", updatedNs1Entity.Aliases[0].Metadata["initial"])
		require.Equal(t, "ns1-new", updatedNs1Entity.Aliases[0].Metadata["added"])

		// Verify updates didn't cross namespaces
		fetchedRootEntity, err := is.entityByAliasFactors(rootCtx, rootAccessor, metadataUser, false)
		require.NoError(t, err)
		require.Equal(t, "root-updated", fetchedRootEntity.Aliases[0].Metadata["initial"])
		require.Equal(t, "root-new", fetchedRootEntity.Aliases[0].Metadata["added"])
		require.NotEqual(t, "ns1-updated", fetchedRootEntity.Aliases[0].Metadata["initial"])

		fetchedNs1Entity, err := is.entityByAliasFactors(ns1Ctx, ns1Accessor, metadataUser, false)
		require.NoError(t, err)
		require.Equal(t, "ns1-updated", fetchedNs1Entity.Aliases[0].Metadata["initial"])
		require.Equal(t, "ns1-new", fetchedNs1Entity.Aliases[0].Metadata["added"])
		require.NotEqual(t, "root-updated", fetchedNs1Entity.Aliases[0].Metadata["initial"])
	})

	// Test namespace hierarchy isolation
	t.Run("namespace_hierarchy_isolation", func(t *testing.T) {
		// Create a child namespace under ns1
		childNs := &namespace.Namespace{ID: "childns", Path: "testns1/childns/"}
		require.NoError(t, c.namespaceStore.SetNamespace(rootCtx, childNs))

		childCtx := namespace.ContextWithNamespace(context.Background(), childNs)

		// Enable userpass auth in child namespace
		childMount := &MountEntry{
			Table:       credentialTableType,
			Path:        "userpass/",
			Type:        "userpass",
			Description: "userpass auth in child",
		}
		err = c.enableCredential(childCtx, childMount)
		require.NoError(t, err)
		childAccessor := childMount.Accessor

		// Create entities in parent and child
		hierarchyUser := "hierarchy-user"

		parentAlias := &logical.Alias{
			Name:          hierarchyUser,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}

		childAlias := &logical.Alias{
			Name:          hierarchyUser,
			MountAccessor: childAccessor,
			MountType:     "userpass",
		}

		parentEntity, _, err := is.CreateOrFetchEntity(ns1Ctx, parentAlias)
		require.NoError(t, err)

		childEntity, _, err := is.CreateOrFetchEntity(childCtx, childAlias)
		require.NoError(t, err)

		// Entities should be in different namespaces
		require.Equal(t, ns1.ID, parentEntity.NamespaceID)
		require.Equal(t, childNs.ID, childEntity.NamespaceID)
		require.NotEqual(t, parentEntity.ID, childEntity.ID)

		// Child namespace should not see parent's entity
		fetchedInChild, err := is.entityByAliasFactors(childCtx, ns1Accessor, hierarchyUser, false)
		require.NoError(t, err)
		require.Nil(t, fetchedInChild, "Child namespace should not see parent's entity")

		// Parent namespace should not see child's entity
		fetchedInParent, err := is.entityByAliasFactors(ns1Ctx, childAccessor, hierarchyUser, false)
		require.NoError(t, err)
		require.Nil(t, fetchedInParent, "Parent namespace should not see child's entity")
	})
}

func TestIdentityStore_NamespaceEdgeCases(t *testing.T) {
	// Register auth backend
	err := AddTestCredentialBackend("userpass", credUserpass.Factory)
	require.NoError(t, err)
	defer ClearTestCredentialBackends()

	// Setup core and namespaces
	c, _, _ := TestCoreUnsealed(t)
	is := c.identityStore
	rootCtx := namespace.RootContext(context.Background())
	ns1, ns2 := setupNamespaces(t, c, rootCtx)

	// Define namespace contexts
	ns1Ctx := namespace.ContextWithNamespace(context.Background(), ns1)
	ns2Ctx := namespace.ContextWithNamespace(context.Background(), ns2)

	// Enable auth methods in different namespaces
	rootMount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in root",
	}
	err = c.enableCredential(rootCtx, rootMount)
	require.NoError(t, err)
	rootAccessor := rootMount.Accessor

	ns1Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns1",
	}
	err = c.enableCredential(ns1Ctx, ns1Mount)
	require.NoError(t, err)
	ns1Accessor := ns1Mount.Accessor

	ns2Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns2",
	}
	err = c.enableCredential(ns2Ctx, ns2Mount)
	require.NoError(t, err)
	ns2Accessor := ns2Mount.Accessor

	t.Run("namespace_mismatch_with_real_mounts", func(t *testing.T) {
		// Create entity in ns1
		mismatchUser := "mismatch-user"
		ns1Alias := &logical.Alias{
			Name:          mismatchUser,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}

		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)
		require.Equal(t, ns1.ID, ns1Entity.NamespaceID)

		// Now try to add an alias from ns2 to this entity
		// Direct attempt to create an entity alias in the wrong namespace
		aliasReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "entity-alias",
			Data: map[string]interface{}{
				"name":           "mismatch-user-2",
				"canonical_id":   ns1Entity.ID, // Entity from ns1
				"mount_accessor": ns2Accessor,  // Accessor from ns2
			},
		}

		resp, err := is.HandleRequest(ns1Ctx, aliasReq)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("Expected error when creating alias with mismatched namespace accessor")
		}

		// Verify entity is not accessible from the wrong namespace.
		updatedEntity, err := is.MemDBEntityByID(rootCtx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.Nil(t, updatedEntity)
	})

	t.Run("orphaned_alias_handling", func(t *testing.T) {
		// Create an entity with alias in ns1
		aliasName := "orphaned-alias-user"
		ns1Alias := &logical.Alias{
			Name:          aliasName,
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}

		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)

		// Create a similar entity in ns2
		ns2Alias := &logical.Alias{
			Name:          aliasName, // Same alias name
			MountAccessor: ns2Accessor,
			MountType:     "userpass",
		}

		ns2Entity, _, err := is.CreateOrFetchEntity(ns2Ctx, ns2Alias)
		require.NoError(t, err)

		// Verify both exist and are separate
		require.NotEqual(t, ns1Entity.ID, ns2Entity.ID, "Entities should be different across namespaces")

		// Delete the entity but not alias in ns1
		_, err = is.HandleRequest(ns1Ctx, &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "entity/id/" + ns1Entity.ID,
		})
		require.NoError(t, err)

		// Verify entity is gone
		deletedEntity, err := is.MemDBEntityByID(ns1Ctx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.Nil(t, deletedEntity, "Entity should be deleted")

		// Try to fetch by the alias - should return nil not error
		orphanedEntity, err := is.entityByAliasFactors(ns1Ctx, ns1Accessor, aliasName, false)
		require.NoError(t, err, "Should not error when alias points to deleted entity")
		require.Nil(t, orphanedEntity, "Should not return entity for orphaned alias")

		// Verify the ns2 entity is still intact
		ns2Lookup, err := is.entityByAliasFactors(ns2Ctx, ns2Accessor, aliasName, false)
		require.NoError(t, err)
		require.NotNil(t, ns2Lookup, "NS2 entity should still exist")
		require.Equal(t, ns2Entity.ID, ns2Lookup.ID)
	})

	t.Run("cross_namespace_merge_attempt", func(t *testing.T) {
		// Create an entity in the root namespace
		rootAlias := &logical.Alias{
			Name:          "merge-test-user",
			MountAccessor: rootAccessor,
			MountType:     "userpass",
		}

		rootEntity, _, err := is.CreateOrFetchEntity(rootCtx, rootAlias)
		require.NoError(t, err)

		// Now try to merge with an entity from ns1
		ns1Alias := &logical.Alias{
			Name:          "merge-victim-user",
			MountAccessor: ns1Accessor,
			MountType:     "userpass",
		}

		ns1Entity, _, err := is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
		require.NoError(t, err)

		// Attempt to merge entities across namespaces
		mergeReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "entity/merge",
			Data: map[string]interface{}{
				"from_entity_ids": []string{ns1Entity.ID},
				"to_entity_id":    rootEntity.ID,
			},
		}

		resp, err := is.HandleRequest(rootCtx, mergeReq)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("Expected error when merging entities across namespaces")
		}

		// Verify both entities still exist separately
		rootCheck, err := is.MemDBEntityByID(rootCtx, rootEntity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, rootCheck, "Root entity should still exist")

		ns1Check, err := is.MemDBEntityByID(ns1Ctx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, ns1Check, "NS1 entity should still exist")
	})

	t.Run("entity_without_namespace", func(t *testing.T) {
		// Create an entity with no namespace ID to test sanitization
		entity := &identity.Entity{
			ID:       "d9d20def-d59e-4a9b-8379-c927ceb7fe10",
			Name:     "test-no-namespace",
			Policies: []string{"default"},
		}

		// Use root context but the entity lacks a namespace ID
		err := is.sanitizeEntity(rootCtx, entity)
		require.NoError(t, err)
		require.Equal(t, namespace.RootNamespaceID, entity.NamespaceID, "Entity should get root namespace ID")
	})

	t.Run("alias_without_namespace", func(t *testing.T) {
		// Create an alias with no namespace ID
		alias := &identity.Alias{
			ID:            "d9d20def-d59e-4a9b-8379-c927ceb7fe10." + ns1.ID,
			CanonicalID:   "test-entity-id",
			MountType:     "userpass",
			MountAccessor: rootAccessor, // Use a valid accessor that exists in the root namespace
			Name:          "test-name",
		}

		// Sanitize should add the namespace from context
		err := is.sanitizeAlias(ns1Ctx, alias)
		require.NoError(t, err)
		require.Equal(t, ns1.ID, alias.NamespaceID, "Alias should get namespace ID from context")
	})

	t.Run("namespace_mismatch", func(t *testing.T) {
		// Create an entity in ns1
		entity := &identity.Entity{
			ID:          "d9d20def-d59e-4a9b-8379-c927ceb7fe10",
			Name:        "mismatch-entity",
			NamespaceID: ns1.ID,
		}

		// Try to use this entity in ns2 context
		err := is.sanitizeEntity(ns2Ctx, entity)
		require.Error(t, err, "Should error when entity namespace doesn't match context namespace")
		require.Contains(t, err.Error(), "not belong to this namespace", "Error should mention namespace mismatch")
	})

	t.Run("concurrent_entity_creation", func(t *testing.T) {
		var wg sync.WaitGroup
		errorChan := make(chan error, 20)
		entityIDs := make(chan string, 20)

		// Create 10 entities concurrently in each namespace
		for i := 0; i < 10; i++ {
			// Root namespace
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				alias := &logical.Alias{
					Name:          fmt.Sprintf("concurrent-user-root-%d", index),
					MountAccessor: rootAccessor,
					MountType:     "userpass",
				}

				entity, _, err := is.CreateOrFetchEntity(rootCtx, alias)
				if err != nil {
					errorChan <- fmt.Errorf("root namespace error: %v", err)
					return
				}
				entityIDs <- entity.ID
			}(i)

			// NS1 namespace
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				alias := &logical.Alias{
					Name:          fmt.Sprintf("concurrent-user-ns1-%d", index),
					MountAccessor: ns1Accessor,
					MountType:     "userpass",
				}

				entity, _, err := is.CreateOrFetchEntity(ns1Ctx, alias)
				if err != nil {
					errorChan <- fmt.Errorf("ns1 namespace error: %v", err)
					return
				}
				entityIDs <- entity.ID
			}(i)
		}

		wg.Wait()
		close(errorChan)
		close(entityIDs)

		// Check for errors
		errors := make([]error, 0)
		for err := range errorChan {
			errors = append(errors, err)
		}
		require.Empty(t, errors, "No errors should occur during concurrent entity creation")

		// Count entities
		ids := make([]string, 0)
		for id := range entityIDs {
			ids = append(ids, id)
		}
		require.Len(t, ids, 20, "Expected 20 entities to be created")

		// Verify uniqueness - all IDs should be unique
		uniqueIDs := make(map[string]bool)
		for _, id := range ids {
			uniqueIDs[id] = true
		}
		require.Len(t, uniqueIDs, 20, "All entity IDs should be unique")
	})
}

// Helper function to setup namespaces for testing
func setupNamespaces(t *testing.T, c *Core, ctx context.Context) (*namespace.Namespace, *namespace.Namespace) {
	ns1 := &namespace.Namespace{ID: "testns1", Path: "testns1/"}
	ns2 := &namespace.Namespace{ID: "testns2", Path: "testns2/"}

	require.NoError(t, c.namespaceStore.SetNamespace(ctx, ns1))
	require.NoError(t, c.namespaceStore.SetNamespace(ctx, ns2))

	return ns1, ns2
}

func setupIdentityTestEnv(t *testing.T, c *Core) (rootCtx context.Context, ns1 *namespace.Namespace, ns1Ctx context.Context, ns2 *namespace.Namespace, ns2Ctx context.Context, rootAccessor string, ns1Accessor string, ns2Accessor string, commonUser string, rootAlias *logical.Alias, ns1Alias *logical.Alias, ns2Alias *logical.Alias, rootEntity *identity.Entity, ns1Entity *identity.Entity, ns2Entity *identity.Entity, groupName string, rootGroup *identity.Group, ns1Group *identity.Group, ns2Group *identity.Group) {
	var err error
	is := c.identityStore
	rootCtx = namespace.RootContext(context.Background())
	ns1, ns2 = setupNamespaces(t, c, rootCtx)

	// Create namespace contexts
	ns1Ctx = namespace.ContextWithNamespace(context.Background(), ns1)
	ns2Ctx = namespace.ContextWithNamespace(context.Background(), ns2)

	// Enable auth methods in all namespaces
	rootMount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in root",
	}
	err = c.enableCredential(rootCtx, rootMount)
	require.NoError(t, err)
	rootAccessor = rootMount.Accessor

	ns1Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns1",
	}
	err = c.enableCredential(ns1Ctx, ns1Mount)
	require.NoError(t, err)
	ns1Accessor = ns1Mount.Accessor

	ns2Mount := &MountEntry{
		Table:       credentialTableType,
		Path:        "userpass/",
		Type:        "userpass",
		Description: "userpass auth in ns2",
	}
	err = c.enableCredential(ns2Ctx, ns2Mount)
	require.NoError(t, err)
	ns2Accessor = ns2Mount.Accessor

	// Create identical aliases in all three namespaces
	commonUser = "isolation-user"

	rootAlias = &logical.Alias{
		Name:          commonUser,
		MountAccessor: rootAccessor,
		MountType:     "userpass",
	}

	ns1Alias = &logical.Alias{
		Name:          commonUser,
		MountAccessor: ns1Accessor,
		MountType:     "userpass",
	}

	ns2Alias = &logical.Alias{
		Name:          commonUser,
		MountAccessor: ns2Accessor,
		MountType:     "userpass",
	}

	rootEntity, _, err = is.CreateOrFetchEntity(rootCtx, rootAlias)
	require.NoError(t, err)

	ns1Entity, _, err = is.CreateOrFetchEntity(ns1Ctx, ns1Alias)
	require.NoError(t, err)

	ns2Entity, _, err = is.CreateOrFetchEntity(ns2Ctx, ns2Alias)
	require.NoError(t, err)

	// Verify all three entities are different
	require.NotEqual(t, rootEntity.ID, ns1Entity.ID)
	require.NotEqual(t, rootEntity.ID, ns2Entity.ID)
	require.NotEqual(t, ns1Entity.ID, ns2Entity.ID)

	// Create group aliases.
	groupName = "isolation-group"

	rootGroup = &identity.Group{
		Name: groupName,
	}

	ns1Group = &identity.Group{
		Name: groupName,
	}

	ns2Group = &identity.Group{
		Name: groupName,
	}

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns2Ctx, ns2Group, nil, nil)
	require.NoError(t, err)

	require.NotEqual(t, rootGroup.ID, ns1Group.ID)
	require.NotEqual(t, rootGroup.ID, ns2Group.ID)
	require.NotEqual(t, ns1Group.ID, ns2Group.ID)

	t.Logf("setupIdentityTestEnv:\n\tns1: accessor=%v / uuid=%v\n\tns2: accessor=%v / uuid=%v\n\tuserpass accessors root=%v / ns1=%v / ns2=%v\n\tentity alias: name=%v / root=%v / ns1=%v / ns2=%v\n\tentity: root=%v / ns1=%v / ns2=%v\n\tgroup: name=%v / root=%v / ns1=%v / ns2=%v", ns1.ID, ns1.UUID, ns2.ID, ns2.UUID, rootAccessor, ns1Accessor, ns2Accessor, commonUser, rootAlias.ID, ns1Alias.ID, ns2Alias.ID, rootEntity.ID, ns1Entity.ID, ns2Entity.ID, groupName, rootGroup.ID, ns1Group.ID, ns2Group.ID)

	return rootCtx, ns1, ns1Ctx, ns2, ns2Ctx, rootAccessor, ns1Accessor, ns2Accessor, commonUser, rootAlias, ns1Alias, ns2Alias, rootEntity, ns1Entity, ns2Entity, groupName, rootGroup, ns1Group, ns2Group
}

// Test cross-namespace isolation with comprehensive matrix of lookup attempts
func TestIdentityStore_CrossNamespaceIsolation(t *testing.T) {
	// Register auth backend
	err := AddTestCredentialBackend("userpass", credUserpass.Factory)
	require.NoError(t, err)
	defer ClearTestCredentialBackends()

	// Setup core and namespaces
	c, _, _ := TestCoreUnsealed(t)
	is := c.identityStore

	rootCtx, ns1, ns1Ctx, ns2, ns2Ctx, rootAccessor, ns1Accessor, ns2Accessor, commonUser, _, _, _, rootEntity, ns1Entity, ns2Entity, _, _, _, _ := setupIdentityTestEnv(t, c)

	// Comprehensive matrix of cross-namespace lookups
	crossLookups := []struct {
		name       string
		ctx        context.Context
		accessor   string
		expectNil  bool
		expectedID string
	}{
		{"root→ns1", rootCtx, ns1Accessor, true, ""},
		{"root→ns2", rootCtx, ns2Accessor, true, ""},
		{"ns1→root", ns1Ctx, rootAccessor, true, ""},
		{"ns1→ns2", ns1Ctx, ns2Accessor, true, ""},
		{"ns2→root", ns2Ctx, rootAccessor, true, ""},
		{"ns2→ns1", ns2Ctx, ns1Accessor, true, ""},
		{"root→root", rootCtx, rootAccessor, false, rootEntity.ID},
		{"ns1→ns1", ns1Ctx, ns1Accessor, false, ns1Entity.ID},
		{"ns2→ns2", ns2Ctx, ns2Accessor, false, ns2Entity.ID},
	}

	for _, test := range crossLookups {
		t.Run(test.name, func(t *testing.T) {
			entity, err := is.entityByAliasFactors(test.ctx, test.accessor, commonUser, false)
			require.NoError(t, err)

			if test.expectNil {
				require.Nil(t, entity, "Should not find entity across namespace boundaries")
			} else {
				require.NotNil(t, entity, "Should find entity in same namespace")
				require.Equal(t, test.expectedID, entity.ID)
			}
		})
	}

	// Test direct entity lookup by ID (should succeed regardless of namespace)
	t.Run("direct_entity_lookup", func(t *testing.T) {
		// Root entity should be retrievable from root context by ID
		entity, err := is.MemDBEntityByID(rootCtx, rootEntity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, entity)
		require.Equal(t, rootEntity.ID, entity.ID)

		// NS1 entity should be retrievable from NS1 context by id
		entity, err = is.MemDBEntityByID(ns1Ctx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.NotNil(t, entity)
		require.Equal(t, ns1Entity.ID, entity.ID)

		// But not visa-versa
		entity, err = is.MemDBEntityByID(ns1Ctx, rootEntity.ID, false)
		require.NoError(t, err)
		require.Nil(t, entity)

		entity, err = is.MemDBEntityByID(rootCtx, ns1Entity.ID, false)
		require.NoError(t, err)
		require.Nil(t, entity)
	})

	// === GROUP ALIASES ===
	// ------------------------------------
	// Test group aliases across namespaces
	t.Run("group_alias_namespace_isolation", func(t *testing.T) {
		commonAliasName := "common-group-alias"

		// --- Setup test data ---
		// -------------------------------------
		// Create groups in each namespace first
		groups := make(map[string]struct {
			ctx      context.Context
			id       string
			ns       *namespace.Namespace
			accessor string
		})

		// Root namespace group
		rootGroupReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "group",
			Data: map[string]interface{}{
				"name":     "test-group-root",
				"type":     "external",
				"policies": []string{"default"},
			},
		}
		resp, err := is.HandleRequest(rootCtx, rootGroupReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "Failed to create root group: %v", resp.Error())

		groups["root"] = struct {
			ctx      context.Context
			id       string
			ns       *namespace.Namespace
			accessor string
		}{
			ctx:      rootCtx,
			id:       resp.Data["id"].(string),
			ns:       namespace.RootNamespace,
			accessor: rootAccessor,
		}

		// NS1 namespace group
		ns1GroupReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "group",
			Data: map[string]interface{}{
				"name":     "test-group-ns1",
				"type":     "external",
				"policies": []string{"default"},
			},
		}
		resp, err = is.HandleRequest(ns1Ctx, ns1GroupReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "Failed to create ns1 group: %v", resp.Error())

		groups["ns1"] = struct {
			ctx      context.Context
			id       string
			ns       *namespace.Namespace
			accessor string
		}{
			ctx:      ns1Ctx,
			id:       resp.Data["id"].(string),
			ns:       ns1,
			accessor: ns1Accessor,
		}

		// NS2 namespace group
		ns2GroupReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "group",
			Data: map[string]interface{}{
				"name":     "test-group-ns2",
				"type":     "external",
				"policies": []string{"default"},
			},
		}
		resp, err = is.HandleRequest(ns2Ctx, ns2GroupReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "Failed to create ns2 group: %v", resp.Error())

		groups["ns2"] = struct {
			ctx      context.Context
			id       string
			ns       *namespace.Namespace
			accessor string
		}{
			ctx:      ns2Ctx,
			id:       resp.Data["id"].(string),
			ns:       ns2,
			accessor: ns2Accessor,
		}

		//  === Create aliases with the same name in each namespace ===
		// -------------------------------------------------------------
		for name, group := range groups {
			aliasReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "group-alias",
				Data: map[string]interface{}{
					"name":           commonAliasName,
					"canonical_id":   group.id,
					"mount_accessor": group.accessor,
				},
			}
			resp, err = is.HandleRequest(group.ctx, aliasReq)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "Failed to create %s group alias: %v", name, resp.Error())
		}

		// === Verify groups have their aliases and correct namespace IDs ===
		// -------------------------------------------------------------------
		for name, group := range groups {
			updatedGroup, err := is.MemDBGroupByID(group.ctx, group.id, true)
			require.NoError(t, err)
			require.NotNil(t, updatedGroup)
			require.NotNil(t, updatedGroup.Alias, "%s group alias should not be nil", name)
			require.Equal(t, commonAliasName, updatedGroup.Alias.Name)
			require.Equal(t, group.ns.ID, updatedGroup.Alias.NamespaceID,
				"%s alias should have %s namespace ID", name, name)
		}

		// ===  Test namespace-aware lookups ===
		// --------------------------------------------------------------
		// Table 1: Valid lookups within the correct namespace
		validLookups := []struct {
			name       string
			ctx        context.Context
			accessor   string
			expectedNS string
		}{
			{"root lookup", rootCtx, rootAccessor, namespace.RootNamespaceID},
			{"ns1 lookup", ns1Ctx, ns1Accessor, ns1.ID},
			{"ns2 lookup", ns2Ctx, ns2Accessor, ns2.ID},
		}

		for _, test := range validLookups {
			t.Run(test.name, func(t *testing.T) {
				aliasLookup, err := is.MemDBAliasByFactorsInTxn(
					is.db(test.ctx).Txn(false),
					test.accessor,
					commonAliasName,
					false,
					true,
				)
				require.NoError(t, err)
				require.NotNil(t, aliasLookup, "%s should find the alias", test.name)
				require.Equal(t, test.expectedNS, aliasLookup.NamespaceID,
					"%s should have correct namespace ID", test.name)

				// Verify group lookup by alias ID works
				groupByAlias, err := is.MemDBGroupByAliasID(test.ctx, aliasLookup.ID, true)
				require.NoError(t, err)
				require.NotNil(t, groupByAlias)
				require.Equal(t, test.expectedNS, groupByAlias.NamespaceID,
					"Group from %s should have correct namespace ID", test.name)
			})
		}

		// Table 2: Cross-namespace lookups that should all return nil
		crossLookups := []struct {
			name      string
			ctx       context.Context
			accessor  string
			expectNil bool
		}{
			{"root→ns1", rootCtx, ns1Accessor, true},
			{"root→ns2", rootCtx, ns2Accessor, true},
			{"ns1→root", ns1Ctx, rootAccessor, true},
			{"ns1→ns2", ns1Ctx, ns2Accessor, true},
			{"ns2→root", ns2Ctx, rootAccessor, true},
			{"ns2→ns1", ns2Ctx, ns1Accessor, true},
		}

		for _, test := range crossLookups {
			t.Run(test.name, func(t *testing.T) {
				aliasLookup, err := is.MemDBAliasByFactorsInTxn(
					is.db(test.ctx).Txn(false),
					test.accessor,
					commonAliasName,
					false,
					true,
				)
				require.NoError(t, err)
				require.Nil(t, aliasLookup,
					"%s should not find alias across namespace boundaries", test.name)
			})
		}
	})
}

func TestIdentityStore_StrictGroupIsloation(t *testing.T) {
	// Register auth backend
	err := AddTestCredentialBackend("userpass", credUserpass.Factory)
	require.NoError(t, err)
	defer ClearTestCredentialBackends()

	// Setup core and namespaces
	c, _, _ := TestCoreUnsealed(t)
	is := c.identityStore

	rootCtx, _, ns1Ctx, _, _, _, _, _, _, _, _, _, _, _, _, _, rootGroup, ns1Group, ns2Group := setupIdentityTestEnv(t, c)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, []string{ns1Group.ID})
	require.Error(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, []string{ns2Group.ID})
	require.Error(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, []string{rootGroup.ID})
	require.Error(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, []string{ns2Group.ID})
	require.Error(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, nil)
	require.NoError(t, err)
}

func TestIdentityStore_UnsafeCrossNamespace(t *testing.T) {
	// Register auth backend
	err := AddTestCredentialBackend("userpass", credUserpass.Factory)
	require.NoError(t, err)
	defer ClearTestCredentialBackends()

	// Setup core and namespaces
	c := TestCoreWithConfig(t, &CoreConfig{
		Seal:            nil,
		EnableUI:        false,
		EnableRaw:       false,
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		AuditBackends: map[string]audit.Factory{
			"file": auditFile.Factory,
		},
		UnsafeCrossNamespaceIdentity: true,
	})

	c, _, _ = testCoreUnsealed(t, c)
	is := c.identityStore

	rootCtx, _, ns1Ctx, _, _, _, _, _, _, _, _, _, _, _, _, _, rootGroup, ns1Group, ns2Group := setupIdentityTestEnv(t, c)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, []string{ns1Group.ID})
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, []string{ns2Group.ID})
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(rootCtx, rootGroup, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, nil)
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, []string{rootGroup.ID})
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, []string{ns2Group.ID})
	require.NoError(t, err)

	err = is.sanitizeAndUpsertGroup(ns1Ctx, ns1Group, nil, nil)
	require.NoError(t, err)
}
