// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"

	"github.com/armon/go-metrics"
	"github.com/go-test/deep"
	uuid "github.com/hashicorp/go-uuid"
	credAppRole "github.com/openbao/openbao/builtin/credential/approle"
	credUserpass "github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/storagepacker"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestIdentityStore_DeleteEntityAlias(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	txn := c.identityStore.db.Txn(true)
	defer txn.Abort()

	alias := &identity.Alias{
		ID:             "testAliasID1",
		CanonicalID:    "testEntityID",
		MountType:      "testMountType",
		MountAccessor:  "testMountAccessor",
		Name:           "testAliasName",
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("testEntityID"),
	}
	alias2 := &identity.Alias{
		ID:             "testAliasID2",
		CanonicalID:    "testEntityID",
		MountType:      "testMountType",
		MountAccessor:  "testMountAccessor2",
		Name:           "testAliasName2",
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("testEntityID"),
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
		BucketKey:   c.identityStore.entityPacker.BucketKey("testEntityID"),
	}

	err := c.identityStore.upsertEntityInTxn(context.Background(), txn, entity, nil, false)
	require.NoError(t, err)

	err = c.identityStore.deleteAliasesInEntityInTxn(txn, entity, []*identity.Alias{alias, alias2})
	require.NoError(t, err)

	txn.Commit()

	alias, err = c.identityStore.MemDBAliasByID("testAliasID1", false, false)
	require.NoError(t, err)
	require.Nil(t, alias)

	alias, err = c.identityStore.MemDBAliasByID("testAliasID2", false, false)
	require.NoError(t, err)
	require.Nil(t, alias)

	entity, err = c.identityStore.MemDBEntityByID("testEntityID", false)
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
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("entity1"),
	}
	entity := &identity.Entity{
		ID:       "entity1",
		Name:     "name1",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker.BucketKey("entity1"),
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
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("entity2"),
	}
	entity2 := &identity.Entity{
		ID:       "entity2",
		Name:     "name2",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias2,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker.BucketKey("entity2"),
	}

	// Persist the second entity directly without the regular flow. This will skip
	// merging of these enties.
	entity2Any, err := ptypes.MarshalAny(entity2)
	if err != nil {
		t.Fatal(err)
	}
	item := &storagepacker.Item{
		ID:      entity2.ID,
		Message: entity2Any,
	}

	ctx := namespace.RootContext(nil)
	if err = c.identityStore.entityPacker.PutItem(ctx, item); err != nil {
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
	is, ghAccessor, core := testIdentityStoreWithAppRoleAuth(ctx, t)
	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: ghAccessor,
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
	if err := core.tokenStore.create(ctx, ent); err != nil {
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
	ctx := namespace.RootContext(nil)
	is, ghAccessor, upAccessor, _ := testIdentityStoreWithAppRoleUserpassAuth(ctx, t)

	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: ghAccessor,
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
	is, ghAccessor, _ := testIdentityStoreWithAppRoleAuth(ctx, t)

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
		"mount_accessor": ghAccessor,
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

	entity, err := is.entityByAliasFactors(ghAccessor, "alias_name", false)
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil {
		t.Fatal("expected a non-nil entity")
	}
	if entity.ID != entityID {
		t.Fatalf("bad: entity ID; expected: %q actual: %q", entityID, entity.ID)
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
	testMakeTokenDirectly(t, ts, te)

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
	testMakeTokenDirectly(t, ts, te)

	// Create a child token; this should inherit the EntityID
	tokenReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "create",
		ClientToken: te.ID,
	}

	ctx := namespace.RootContext(nil)
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
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("entity1"),
	}
	entity := &identity.Entity{
		ID:       "entity1",
		Name:     "name1",
		Policies: []string{"foo", "bar"},
		Aliases: []*identity.Alias{
			alias,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker.BucketKey("entity1"),
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
		LocalBucketKey: c.identityStore.localAliasPacker.BucketKey("entity2"),
	}
	entity2 := &identity.Entity{
		ID:       "entity2",
		Name:     "name2",
		Policies: []string{"bar", "baz"},
		Aliases: []*identity.Alias{
			alias2,
		},
		NamespaceID: namespace.RootNamespaceID,
		BucketKey:   c.identityStore.entityPacker.BucketKey("entity2"),
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

	newEntity, err = c.identityStore.MemDBEntityByID(entityToUse, false)
	if err != nil {
		t.Fatal(err)
	}
	if newEntity != nil {
		t.Fatal("got a non-nil entity")
	}
}

func testCoreWithIdentityTokenAppRole(ctx context.Context, t *testing.T) (*Core, *IdentityStore, *TokenStore, string) {
	is, ghAccessor, core := testIdentityStoreWithAppRoleAuth(ctx, t)
	return core, is, core.tokenStore, ghAccessor
}

func testCoreWithIdentityTokenAppRoleRoot(ctx context.Context, t *testing.T) (*Core, *IdentityStore, *TokenStore, string, string) {
	is, ghAccessor, core, root := testIdentityStoreWithAppRoleAuthRoot(ctx, t)
	return core, is, core.tokenStore, ghAccessor, root
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

func testIdentityStoreWithAppRoleUserpassAuth(ctx context.Context, t *testing.T) (*IdentityStore, string, string, *Core) {
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

	c, _, _ := TestCoreUnsealed(t)

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
	ghAccessor := meGH.Accessor

	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: ghAccessor,
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
	ctx := context.Background()

	// add caseSensitivityKey to storage
	entry, err := logical.StorageEntryJSON(caseSensitivityKey, &casesensitivity{
		DisableLowerCasedNames: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.identityStore.view.Put(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}

	// check if the value is stored in storage
	storageEntry, err := c.identityStore.view.Get(ctx, caseSensitivityKey)
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
	storageEntry, err = c.identityStore.view.Get(ctx, caseSensitivityKey)
	if err != nil {
		t.Fatal(err)
	}

	if storageEntry != nil {
		t.Fatal("bad: expected no entry for casesensitivity key")
	}
}
