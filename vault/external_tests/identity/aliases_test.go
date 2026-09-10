// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	sqjwt "github.com/go-jose/go-jose/v4/jwt"
	auth "github.com/openbao/openbao/api/auth/userpass/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/approle"
	"github.com/openbao/openbao/builtin/credential/cert"
	jwtauth "github.com/openbao/openbao/builtin/credential/jwt"
	"github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/helper/testhelpers"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
)

func TestIdentityStore_CaseSensitiveEntityAliases(t *testing.T) {
	// Define certs
	ca := certyaml.Certificate{
		Subject: "cn=ca",
	}
	adminCert := certyaml.Certificate{
		Subject:     "cn=admin",
		Issuer:      &ca,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	imposterCert := certyaml.Certificate{
		Subject: "cn=Admin",
		Issuer:  &ca,
	}

	// Start a cluster with custom CA
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": cert.Factory,
		},
	}
	cert, err := ca.TLSCertificate()
	require.NoError(t, err)
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		CACert:      cert.Certificate[0],
		CAKey:       cert.PrivateKey.(*ecdsa.PrivateKey),
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Enable and configure cert auth
	err = client.Sys().EnableAuthWithOptionsWithContext(t.Context(), "cert", &api.EnableAuthOptions{
		Type: "cert",
		Config: api.MountConfigInput{
			CaseSensitiveAlias: new(true),
		},
	})
	require.NoError(t, err)

	_, err = client.Logical().WriteWithContext(t.Context(), "auth/cert/certs/my-ca", map[string]any{
		"certificate":    string(ca.CertPEM()),
		"token_policies": "",
		"token_ttl":      "30m",
		"display_name":   "My CA",
	})
	require.NoError(t, err)

	// Login once to create entity
	conf := api.NewConfig()
	conf.Address = client.Address()
	require.NoError(t, conf.ConfigureTLS(&api.TLSConfig{
		ClientCertBytes: adminCert.CertPEM(),
		ClientKeyBytes:  adminCert.KeyPEM(),
		CACertBytes:     ca.CertPEM(),
	}))

	admin, err := api.NewClient(conf)
	require.NoError(t, err)

	resp, err := admin.Logical().WriteWithContext(t.Context(), "auth/cert/login", map[string]any{
		"name": "my-ca",
	})
	require.NoError(t, err)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	require.Equal(t, []string{"default"}, resp.Auth.Policies)

	// Grant policy to entity
	_, err = client.Logical().WriteWithContext(t.Context(), "identity/entity/id/"+resp.Auth.EntityID,
		map[string]any{"policies": []string{"admin"}})
	require.NoError(t, err)

	// Login again: admin should now have the new policy
	resp, err = admin.Logical().WriteWithContext(t.Context(), "auth/cert/login", map[string]any{
		"name": "my-ca",
	})
	require.NoError(t, err)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	require.Equal(t, []string{"admin", "default"}, resp.Auth.Policies)

	// Login as imposter: should not have the policy, entity id should be different
	conf = api.NewConfig()
	conf.Address = client.Address()
	require.NoError(t, conf.ConfigureTLS(&api.TLSConfig{
		ClientCertBytes: imposterCert.CertPEM(),
		ClientKeyBytes:  imposterCert.KeyPEM(),
		CACertBytes:     ca.CertPEM(),
	}))

	imposter, err := api.NewClient(conf)
	require.NoError(t, err)

	imposterResp, err := imposter.Logical().WriteWithContext(t.Context(), "auth/cert/login", map[string]any{
		"name": "my-ca",
	})
	require.NoError(t, err)

	require.NotNil(t, imposterResp)
	require.NotNil(t, imposterResp.Auth)
	assert.Equal(t, []string{"default"}, imposterResp.Auth.Policies)
	assert.NotEqual(t, resp.Auth.EntityID, imposterResp.Auth.EntityID)

	// delete the mount and restart the cluster => unseal should succeed
	err = client.Sys().DisableAuthWithContext(t.Context(), "cert")
	require.NoError(t, err)

	cluster.EnsureCoresSealed(t)
	cluster.UnsealCores(t)
}

func TestIdentityStore_CaseSensitiveGroupAliases(t *testing.T) {
	// Generate key-pair for jwt
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	require.NoError(t, err)

	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDer,
	}))

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	getJWT := func(alias string, groups string) string {
		jwt, err := sqjwt.Signed(sig).Claims(sqjwt.Claims{
			Audience: sqjwt.Audience{"test"},
			IssuedAt: sqjwt.NewNumericDate(time.Now()),
			Expiry:   sqjwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).Claims(map[string]any{
			"alias":  alias,
			"groups": groups,
		}).Serialize()
		require.NoError(t, err)
		return jwt
	}

	// Start cluster
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"jwt": jwtauth.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Enable and configure jwt auth
	err = client.Sys().EnableAuthWithOptionsWithContext(t.Context(), "jwt", &api.EnableAuthOptions{
		Type: "jwt",
		Config: api.MountConfigInput{
			CaseSensitiveAlias: new(true),
		},
	})
	require.NoError(t, err)

	resp, err := client.Logical().ReadWithContext(t.Context(), "sys/auth/jwt")
	require.NoError(t, err)
	require.NotNil(t, resp)
	jwtAccessor := resp.Data["accessor"]

	_, err = client.Logical().WriteWithContext(t.Context(), "auth/jwt/config", map[string]any{
		"jwt_validation_pubkeys": pubPem,
	})
	require.NoError(t, err)

	_, err = client.Logical().WriteWithContext(t.Context(), "auth/jwt/role/my-role", map[string]any{
		"role_type":       "jwt",
		"user_claim":      "alias",
		"groups_claim":    "groups",
		"bound_audiences": "test",
	})
	require.NoError(t, err)

	// Create group
	resp, err = client.Logical().WriteWithContext(t.Context(), "identity/group",
		map[string]any{
			"name":     "admins",
			"policies": []string{"admin"},
			"type":     "external",
		},
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	groupId := resp.Data["id"].(string)

	// Create group alias
	_, err = client.Logical().WriteWithContext(t.Context(), "identity/group-alias",
		map[string]any{
			"name":           "jwt-admins",
			"mount_accessor": jwtAccessor,
			"canonical_id":   groupId,
		},
	)
	require.NoError(t, err)

	// Login as Admin
	resp, err = client.Logical().WriteWithContext(t.Context(), "auth/jwt/login", map[string]any{
		"role": "my-role",
		"jwt":  getJWT("alice", "jwt-admins"),
	})
	require.NoError(t, err)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	adminEntityId := resp.Auth.EntityID
	require.ElementsMatch(t, []string{"admin", "default"}, resp.Auth.Policies) // expect admin policy

	// Login as Impostor
	resp, err = client.Logical().WriteWithContext(t.Context(), "auth/jwt/login", map[string]any{
		"role": "my-role",
		"jwt":  getJWT("impostor", "JWT-ADMINS"),
	})
	require.NoError(t, err)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	assert.ElementsMatch(t, []string{"default"}, resp.Auth.Policies) // expect no admin policy

	// Check group members
	resp, err = client.Logical().ReadWithContext(t.Context(), "identity/group/id/"+groupId)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, []string{adminEntityId}, resp.Data["member_entity_ids"])
}

// TODO: rewrite test to not rely on AppRole plugin.
func TestIdentityStore_ListAlias(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}
	var approleAccessor string
	for k, v := range mounts {
		t.Logf("key: %v\nmount: %#v", k, *v)
		if k == "approle/" {
			approleAccessor = v.Accessor
			break
		}
	}
	if approleAccessor == "" {
		t.Fatal("did not find approle accessor")
	}

	resp, err := client.Logical().Write("identity/entity", nil)
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected a non-nil response")
	}

	entityID := resp.Data["id"].(string)

	// Create an alias
	resp, err = client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "testaliasname",
		"mount_accessor": approleAccessor,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	testAliasCanonicalID := resp.Data["canonical_id"].(string)
	testAliasAliasID := resp.Data["id"].(string)

	resp, err = client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "entityalias",
		"mount_accessor": approleAccessor,
		"canonical_id":   entityID,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	entityAliasAliasID := resp.Data["id"].(string)

	resp, err = client.Logical().List("identity/entity-alias/id")
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	keys := resp.Data["keys"].([]interface{})
	if len(keys) != 2 {
		t.Fatalf("bad: length of alias IDs listed; expected: 2, actual: %d", len(keys))
	}

	// Do some due diligence on the key info
	aliasInfoRaw, ok := resp.Data["key_info"]
	if !ok {
		t.Fatal("expected key_info map in response")
	}
	aliasInfo := aliasInfoRaw.(map[string]interface{})
	for _, keyRaw := range keys {
		key := keyRaw.(string)
		infoRaw, ok := aliasInfo[key]
		if !ok {
			t.Fatal("expected key info")
		}
		info := infoRaw.(map[string]interface{})
		currName := "entityalias"
		if info["canonical_id"].(string) == testAliasCanonicalID {
			currName = "testaliasname"
		}
		t.Logf("alias info: %#v", info)
		switch {
		case info["name"].(string) != currName:
			t.Fatalf("bad name: %v", info["name"].(string))
		case info["mount_accessor"].(string) != approleAccessor:
			t.Fatalf("bad mount_path: %v", info["mount_accessor"].(string))
		}
	}

	// Now do the same with entity info
	resp, err = client.Logical().List("identity/entity/id")
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	keys = resp.Data["keys"].([]interface{})
	if len(keys) != 2 {
		t.Fatalf("bad: length of entity IDs listed; expected: 2, actual: %d", len(keys))
	}

	entityInfoRaw, ok := resp.Data["key_info"]
	if !ok {
		t.Fatal("expected key_info map in response")
	}

	// This is basically verifying that the entity has the alias in key_info
	// that we expect to be tied to it, plus tests a value further down in it
	// for fun
	entityInfo := entityInfoRaw.(map[string]interface{})
	for _, keyRaw := range keys {
		key := keyRaw.(string)
		infoRaw, ok := entityInfo[key]
		if !ok {
			t.Fatal("expected key info")
		}
		info := infoRaw.(map[string]interface{})
		t.Logf("entity info: %#v", info)
		currAliasID := entityAliasAliasID
		if key == testAliasCanonicalID {
			currAliasID = testAliasAliasID
		}
		currAliases := info["aliases"].([]interface{})
		if len(currAliases) != 1 {
			t.Fatal("bad aliases length")
		}
		for _, v := range currAliases {
			curr := v.(map[string]interface{})
			switch {
			case curr["id"].(string) != currAliasID:
				t.Fatalf("bad alias id: %v", curr["id"])
			case curr["mount_accessor"].(string) != approleAccessor:
				t.Fatalf("bad mount accessor: %v", curr["mount_accessor"])
			case curr["mount_path"].(string) != "auth/approle/":
				t.Fatalf("bad mount path: %v", curr["mount_path"])
			case curr["mount_type"].(string) != "approle":
				t.Fatalf("bad mount type: %v", curr["mount_type"])
			}
		}
	}
}

// TestIdentityStore_RenameAlias_CannotMergeEntity verifies that an error is
// returned on an attempt to rename an alias to match another alias with the
// same mount accessor.  This used to result in a merge entity.
func TestIdentityStore_RenameAlias_CannotMergeEntity(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bsmith", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	// Now create a new unrelated entity and alias
	entityResp, err := client.Logical().Write("identity/entity", map[string]interface{}{
		"name": "bob-smith",
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, entityResp)
	}
	if entityResp == nil {
		t.Fatal("expected a non-nil response")
	}

	aliasResp, err := client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "bob",
		"mount_accessor": mountAccessor,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, aliasResp)
	}
	aliasID2 := aliasResp.Data["id"].(string)

	// Rename this new alias to have the same name as the one implicitly created by our login as bsmith
	_, err = client.Logical().Write("identity/entity-alias/id/"+aliasID2, map[string]interface{}{
		"name": "bsmith",
	})
	if err == nil {
		t.Fatal("expected rename over existing entity to fail")
	}
}

func TestIdentityStore_MergeEntities_FailsDueToClash(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	_, entityIdBob, aliasIdBob := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")

	// Create userpass login for alice
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, entityIdAlice, aliasIdAlice := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "alice-smith", "alice")

	// Perform entity merge
	mergeResp, err := client.Logical().Write("identity/entity/merge", map[string]interface{}{
		"to_entity_id":    entityIdBob,
		"from_entity_ids": entityIdAlice,
	})
	if err == nil {
		t.Fatalf("Expected error upon merge. Resp:%#v", mergeResp)
	}
	if !strings.Contains(err.Error(), "toEntity and at least one fromEntity have aliases with the same mount accessor") {
		t.Fatalf("Error was not due to conflicting alias mount accessors. Error: %v", err)
	}
	if !strings.Contains(err.Error(), entityIdAlice) {
		t.Fatalf("Did not identify alice's entity (%s) as conflicting. Error: %v", entityIdAlice, err)
	}
	if !strings.Contains(err.Error(), entityIdBob) {
		t.Fatalf("Did not identify bob's entity (%s) as conflicting. Error: %v", entityIdBob, err)
	}
	if !strings.Contains(err.Error(), aliasIdAlice) {
		t.Fatalf("Did not identify alice's alias (%s) as conflicting. Error: %v", aliasIdAlice, err)
	}
	if !strings.Contains(err.Error(), aliasIdBob) {
		t.Fatalf("Did not identify bob's alias (%s) as conflicting. Error: %v", aliasIdBob, err)
	}
	if !strings.Contains(err.Error(), mountAccessor) {
		t.Fatalf("Did not identify mount accessor %s as being reason for conflict. Error: %v", mountAccessor, err)
	}
}

// TODO: rewrite test to not rely on AppRole plugin
func TestIdentityStore_MergeEntities_FailsDueToClashInFromEntities(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
			"approle":  approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	var mountAccessorAppRole string
	for k, v := range mounts {
		if k == "approle/" {
			mountAccessorAppRole = v.Accessor
			break
		}
	}
	if mountAccessorAppRole == "" {
		t.Fatal("did not find approle accessor")
	}

	_, entityIdBob, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")
	_, entityIdAlice, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessorAppRole, "alice-smith", "alice")
	_, entityIdClara, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessorAppRole, "clara-smith", "clara")

	// Perform entity merge
	mergeResp, err := client.Logical().Write("identity/entity/merge", map[string]interface{}{
		"to_entity_id":    entityIdBob,
		"from_entity_ids": []string{entityIdAlice, entityIdClara},
	})
	if err == nil {
		t.Fatalf("Expected error upon merge. Resp:%#v", mergeResp)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("mount accessor %s found in multiple fromEntities, merge should be done with one fromEntity at a time", mountAccessorAppRole)) {
		t.Fatalf("Error was not due to conflicting alias mount accessors in fromEntities. Error: %v", err)
	}
}

func TestIdentityStore_MergeEntities_FailsDueToDoubleClash(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
			"approle":  approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob-approle", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	var mountAccessorAppRole string
	for k, v := range mounts {
		if k == "approle/" {
			mountAccessorAppRole = v.Accessor
			break
		}
	}
	if mountAccessorAppRole == "" {
		t.Fatal("did not find approle accessor")
	}

	_, entityIdBob, aliasIdBob := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")

	aliasResp, err := client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "bob-approle",
		"canonical_id":   entityIdBob,
		"mount_accessor": mountAccessorAppRole,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, aliasResp)
	}

	aliasIdBobAppRole := aliasResp.Data["id"].(string)
	if aliasIdBobAppRole == "" {
		t.Fatal("Alias ID not present in response")
	}

	// Create userpass login for alice
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, entityIdAlice, aliasIdAlice := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "alice-smith", "alice")
	_, entityIdClara, aliasIdClara := testhelpers.CreateEntityAndAlias(t, client, mountAccessorAppRole, "clara-smith", "clara")

	// Perform entity merge
	mergeResp, err := client.Logical().Write("identity/entity/merge", map[string]interface{}{
		"to_entity_id":    entityIdBob,
		"from_entity_ids": []string{entityIdAlice, entityIdClara},
	})
	if err == nil {
		t.Fatalf("Expected error upon merge. Resp:%#v", mergeResp)
	}
	if mergeResp != nil {
		t.Fatalf("Response was non-nil. Resp:%#v", mergeResp)
	}
	if !strings.Contains(err.Error(), "toEntity and at least one fromEntity have aliases with the same mount accessor") {
		t.Fatalf("Error was not due to conflicting alias mount accessors. Error: %v", err)
	}
	if !strings.Contains(err.Error(), entityIdAlice) {
		t.Fatalf("Did not identify alice's entity (%s) as conflicting. Error: %v", entityIdAlice, err)
	}
	if !strings.Contains(err.Error(), entityIdBob) {
		t.Fatalf("Did not identify bob's entity (%s) as conflicting. Error: %v", entityIdBob, err)
	}
	if !strings.Contains(err.Error(), entityIdClara) {
		t.Fatalf("Did not identify clara's alias (%s) as conflicting. Error: %v", entityIdClara, err)
	}
	if !strings.Contains(err.Error(), aliasIdAlice) {
		t.Fatalf("Did not identify alice's alias (%s) as conflicting. Error: %v", aliasIdAlice, err)
	}
	if !strings.Contains(err.Error(), aliasIdBob) {
		t.Fatalf("Did not identify bob's alias (%s) as conflicting. Error: %v", aliasIdBob, err)
	}
	if !strings.Contains(err.Error(), aliasIdClara) {
		t.Fatalf("Did not identify bob's alias (%s) as conflicting. Error: %v", aliasIdClara, err)
	}
	if !strings.Contains(err.Error(), mountAccessor) {
		t.Fatalf("Did not identify mount accessor %s as being reason for conflict. Error: %v", mountAccessor, err)
	}
	if !strings.Contains(err.Error(), mountAccessorAppRole) {
		t.Fatalf("Did not identify mount accessor %s as being reason for conflict. Error: %v", mountAccessorAppRole, err)
	}
}

func TestIdentityStore_MergeEntities_FailsDueToClashInFromEntities_CheckRawRequest(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	_, entityIdBob, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")

	// Create userpass login for alice
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]interface{}{
		"password": "training",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, entityIdAlice, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "alice-smith", "alice")

	// Perform entity merge as a Raw Request so we can investigate the response body
	req := client.NewRequest("POST", "/v1/identity/entity/merge")
	req.SetJSONBody(map[string]interface{}{
		"to_entity_id":    entityIdBob,
		"from_entity_ids": []string{entityIdAlice},
	})

	resp, err := client.RawRequest(req)
	if err == nil {
		t.Fatalf("Expected error but did not get one. Response: %v", resp)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	bodyString := string(bodyBytes)

	if resp.StatusCode != 400 {
		t.Fatal("Incorrect status code for response")
	}

	var mapOutput map[string]interface{}
	if err = json.Unmarshal([]byte(bodyString), &mapOutput); err != nil {
		t.Fatal(err)
	}

	errorStrings, ok := mapOutput["errors"].([]interface{})
	if !ok {
		t.Fatalf("error not present in response - full response: %s", bodyString)
	}

	if len(errorStrings) != 1 {
		t.Fatalf("Incorrect number of errors in response - full response: %s", bodyString)
	}

	errorString, ok := errorStrings[0].(string)
	if !ok {
		t.Fatalf("error not present in response - full response: %s", bodyString)
	}

	if !strings.Contains(errorString, "toEntity and at least one fromEntity have aliases with the same mount accessor") {
		t.Fatalf("Error was not due to conflicting alias mount accessors. Error: %s", errorString)
	}

	dataArray, ok := mapOutput["data"].([]interface{})
	if !ok {
		t.Fatalf("data not present in response - full response: %s", bodyString)
	}

	if len(dataArray) != 2 {
		t.Fatalf("Incorrect amount of clash data in response - full response: %s", bodyString)
	}

	for _, data := range dataArray {
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			t.Fatalf("data could not be understood - full response: %s", bodyString)
		}

		entityId, ok := dataMap["entity_id"].(string)
		if !ok {
			t.Fatalf("entity_id not present in data - full response: %s", bodyString)
		}

		if entityId != entityIdBob && entityId != entityIdAlice {
			t.Fatalf("entityId not bob or alice - full response: %s", bodyString)
		}

		entity, ok := dataMap["entity"].(string)
		if !ok {
			t.Fatalf("entity not present in data - full response: %s", bodyString)
		}

		if entity != "bob-smith" && entity != "alice-smith" {
			t.Fatalf("entity not bob or alice - full response: %s", bodyString)
		}

		alias, ok := dataMap["alias"].(string)
		if !ok {
			t.Fatalf("alias not present in data - full response: %s", bodyString)
		}

		if alias != "bob" && alias != "alice" {
			t.Fatalf("alias not bob or alice - full response: %s", bodyString)
		}

		mountPath, ok := dataMap["mount_path"].(string)
		if !ok {
			t.Fatalf("mountPath not present in data - full response: %s", bodyString)
		}

		if mountPath != "auth/userpass/" {
			t.Fatalf("mountPath not auth/userpass/ - full response: %s", bodyString)
		}

		mount, ok := dataMap["mount"].(string)
		if !ok {
			t.Fatalf("mount not present in data - full response: %s", bodyString)
		}

		if mount != "userpass" {
			t.Fatalf("mount not userpass - full response: %s", bodyString)
		}
	}
}

func TestIdentityStore_MergeEntities_SameMountAccessor_ThenUseAlias(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Logical().Write("auth/userpass/login/bob", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	_, entityIdBob, aliasIdBob := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")

	// Create userpass login for alice
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Logical().Write("auth/userpass/login/alice", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, entityIdAlice, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "alice-smith", "alice")

	// Try and login with alias 2 (alice) pre-merge
	userpassAuth, err := auth.NewUserpassAuth("alice", &auth.Password{FromString: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}
	loginResp, err := client.Logical().Write("auth/userpass/login/alice", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, loginResp)
	}
	if loginResp.Auth == nil {
		t.Fatalf("Request auth is nil, something has gone wrong - resp:%#v", loginResp)
	}
	loginEntityId := loginResp.Auth.EntityID
	if loginEntityId != entityIdAlice {
		t.Fatalf("Login entity ID is not Alice. loginEntityId:%s aliceEntityId:%s", loginEntityId, entityIdAlice)
	}

	// Perform entity merge
	mergeResp, err := client.Logical().Write("identity/entity/merge", map[string]interface{}{
		"to_entity_id":                  entityIdBob,
		"from_entity_ids":               entityIdAlice,
		"conflicting_alias_ids_to_keep": aliasIdBob,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, mergeResp)
	}

	// Delete entity id 1 (bob)
	deleteResp, err := client.Logical().Delete(fmt.Sprintf("identity/entity/id/%s", entityIdBob))
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, deleteResp)
	}

	// Try and login with alias 2 (alice) post-merge
	// Notably, this login method sets the client token, which is why we didn't use it above
	loginResp, err = client.Auth().Login(t.Context(), userpassAuth)
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, loginResp)
	}
	if loginResp.Auth == nil {
		t.Fatalf("Request auth is nil, something has gone wrong - resp:%#v", loginResp)
	}
	if loginEntityId != entityIdAlice {
		t.Fatalf("Login entity ID is not Alice. loginEntityId:%s aliceEntityId:%s", loginEntityId, entityIdAlice)
	}
}

// TODO: rewrite test to not rely on AppRole plugin.
func TestIdentityStore_MergeEntities_FailsDueToMultipleClashMergesAttempted(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
			"approle":  approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/bob-approle", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var mountAccessor string
	for k, v := range mounts {
		if k == "userpass/" {
			mountAccessor = v.Accessor
			break
		}
	}
	if mountAccessor == "" {
		t.Fatal("did not find userpass accessor")
	}

	var mountAccessorAppRole string
	for k, v := range mounts {
		if k == "approle/" {
			mountAccessorAppRole = v.Accessor
			break
		}
	}
	if mountAccessorAppRole == "" {
		t.Fatal("did not find approle accessor")
	}

	_, entityIdBob, _ := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "bob-smith", "bob")
	aliasResp, err := client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "bob-approle",
		"canonical_id":   entityIdBob,
		"mount_accessor": mountAccessorAppRole,
	})
	if err != nil {
		t.Fatalf("err:%v resp:%#v", err, aliasResp)
	}

	aliasIdBobAppRole := aliasResp.Data["id"].(string)
	if aliasIdBobAppRole == "" {
		t.Fatal("Alias ID not present in response")
	}

	// Create userpass login for alice
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, entityIdAlice, aliasIdAlice := testhelpers.CreateEntityAndAlias(t, client, mountAccessor, "alice-smith", "alice")
	_, entityIdClara, aliasIdClara := testhelpers.CreateEntityAndAlias(t, client, mountAccessorAppRole, "clara-smith", "alice")

	// Perform entity merge
	mergeResp, err := client.Logical().Write("identity/entity/merge", map[string]interface{}{
		"to_entity_id":                  entityIdBob,
		"from_entity_ids":               []string{entityIdAlice, entityIdClara},
		"conflicting_alias_ids_to_keep": []string{aliasIdAlice, aliasIdClara},
	})
	if err == nil {
		t.Fatalf("Expected error upon merge. Resp:%#v", mergeResp)
	}
	if !strings.Contains(err.Error(), "merge one entity at a time") {
		t.Fatalf("did not error for the right reason. Error: %v", err)
	}
}
