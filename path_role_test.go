package jwtauth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPath_Create(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":       "jwt",
		"bound_subject":   "testsub",
		"bound_audiences": "vault",
		"user_claim":      "user",
		"groups_claim":    "groups",
		"bound_cidrs":     "127.0.0.1/8",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	expectedSockAddr, err := sockaddr.NewSockAddr("127.0.0.1/8")
	if err != nil {
		t.Fatal(err)
	}

	expected := &jwtRole{
		RoleType:            "jwt",
		Policies:            []string{"test"},
		Period:              3 * time.Second,
		BoundSubject:        "testsub",
		BoundAudiences:      []string{"vault"},
		UserClaim:           "user",
		GroupsClaim:         "groups",
		TTL:                 1 * time.Second,
		MaxTTL:              5 * time.Second,
		NumUses:             12,
		BoundCIDRs:          []*sockaddr.SockAddrMarshaler{{expectedSockAddr}},
		AllowedRedirectURIs: []string{},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	actual, err := b.(*jwtAuthBackend).role(context.Background(), storage, "plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
	}

	// Test no user claim
	data = map[string]interface{}{
		"policies": "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "a user claim must be defined on the role" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test no binding
	data = map[string]interface{}{
		"role_type":  "jwt",
		"user_claim": "user",
		"policies":   "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "must have at least one bound constraint") {
		t.Fatalf("unexpected err: %v", resp)
	}
}

func TestPath_OIDCCreate(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"bound_audiences": "vault",
		"bound_claims": map[string]interface{}{
			"foo": 10,
			"bar": "baz",
		},
		"oidc_scopes":           []string{"email", "profile"},
		"allowed_redirect_uris": []string{"https://example.com", "http://localhost:8300"},
		"claim_mappings": map[string]string{
			"foo": "a",
			"bar": "b",
		},
		"user_claim":   "user",
		"groups_claim": "groups",
		"policies":     "test",
		"period":       "3s",
		"ttl":          "1s",
		"num_uses":     12,
		"max_ttl":      "5s",
	}

	expected := &jwtRole{
		RoleType:       "oidc",
		Policies:       []string{"test"},
		Period:         3 * time.Second,
		BoundAudiences: []string{"vault"},
		BoundClaims: map[string]interface{}{
			"foo": json.Number("10"),
			"bar": "baz",
		},
		AllowedRedirectURIs: []string{"https://example.com", "http://localhost:8300"},
		ClaimMappings: map[string]string{
			"foo": "a",
			"bar": "b",
		},
		OIDCScopes:  []string{"email", "profile"},
		UserClaim:   "user",
		GroupsClaim: "groups",
		TTL:         1 * time.Second,
		MaxTTL:      5 * time.Second,
		NumUses:     12,
	}

	// test both explicit and default role_type
	for _, roleType := range []string{"", "oidc"} {
		data["role_type"] = roleType
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/plugin-test",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
		actual, err := b.(*jwtAuthBackend).role(context.Background(), storage, "plugin-test")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(expected, actual); diff != nil {
			t.Fatal(diff)
		}
	}

	// Test invalid reserved metadata key 'role'
	data["claim_mappings"] = map[string]string{
		"foo":        "a",
		"some_claim": "role",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.Contains(resp.Error().Error(), "metadata key 'role' is reserved") {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test invalid duplicate metadata destination
	data["claim_mappings"] = map[string]string{
		"foo": "a",
		"bar": "a",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.Contains(resp.Error().Error(), "multiple keys are mapped to metadata key 'a'") {
		t.Fatalf("unexpected err: %v", resp)
	}
}

func TestPath_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":       "jwt",
		"bound_subject":   "testsub",
		"bound_audiences": "vault",
		"user_claim":      "user",
		"groups_claim":    "groups",
		"bound_cidrs":     "127.0.0.1/8",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	expected := map[string]interface{}{
		"role_type":             "jwt",
		"bound_claims":          map[string]interface{}(nil),
		"claim_mappings":        map[string]string(nil),
		"bound_subject":         "testsub",
		"bound_audiences":       []string{"vault"},
		"allowed_redirect_uris": []string{},
		"user_claim":            "user",
		"groups_claim":          "groups",
		"policies":              []string{"test"},
		"period":                int64(3),
		"ttl":                   int64(1),
		"num_uses":              12,
		"max_ttl":               int64(5),
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["bound_cidrs"].([]*sockaddr.SockAddrMarshaler)[0].String() != "127.0.0.1/8" {
		t.Fatal("unexpected bound cidrs")
	}
	delete(resp.Data, "bound_cidrs")
	if diff := deep.Equal(expected, resp.Data); diff != nil {
		t.Fatal(diff)
	}
}

func TestPath_Delete(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":       "jwt",
		"bound_subject":   "testsub",
		"bound_audiences": "vault",
		"user_claim":      "user",
		"groups_claim":    "groups",
		"bound_cidrs":     "127.0.0.1/8",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}
}
