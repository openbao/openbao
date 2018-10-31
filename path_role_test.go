package jwtauth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-sockaddr"
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
		Policies:       []string{"test"},
		Period:         3 * time.Second,
		BoundSubject:   "testsub",
		BoundAudiences: []string{"vault"},
		UserClaim:      "user",
		GroupsClaim:    "groups",
		TTL:            1 * time.Second,
		MaxTTL:         5 * time.Second,
		NumUses:        12,
		BoundCIDRs:     []*sockaddr.SockAddrMarshaler{&sockaddr.SockAddrMarshaler{expectedSockAddr}},
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
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "a user claim must be defined on the role" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test no binding
	data = map[string]interface{}{
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
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "must have at least one bound constraint") {
		t.Fatalf("unexpected err: %v", resp)
	}
}

func TestPath_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
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
		"bound_subject":                  "testsub",
		"bound_audiences":                []string{"vault"},
		"user_claim":                     "user",
		"groups_claim":                   "groups",
		"groups_claim_delimiter_pattern": "",
		"policies":                       []string{"test"},
		"period":                         int64(3),
		"ttl":                            int64(1),
		"num_uses":                       12,
		"max_ttl":                        int64(5),
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
	if !reflect.DeepEqual(expected, resp.Data) {
		t.Fatalf("Unexpected role data: expected \n%#v\n got \n%#v\n", expected, resp.Data)
	}
}

func TestPath_Delete(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
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

func TestParseClaimWithDelimiters(t *testing.T) {
	type tc struct {
		name string
		c    string
		d    string
		res  []string
		err  error
	}

	testCases := []tc{
		{
			name: "nodelim",
			c:    "groups",
			res:  []string{"groups"},
		},
		{
			name: "multi",
			c:    "gr.o/u.ps",
			d:    "./.",
			res:  []string{"gr", "o", "u", "ps"},
		},
		{
			name: "multiextradelims",
			c:    "gr.o/u.ps",
			d:    "./..",
			err:  errors.New(`could not find instance of "." delimiter in claim`),
		},
		{
			name: "delimnotfound",
			c:    "groups",
			d:    ".",
			err:  errors.New(`could not find instance of "." delimiter in claim`),
		},
		{
			name: "delimatend",
			c:    "groups.",
			d:    ".",
			err:  errors.New(`instance of "." delimiter in claim is at end of claim string`),
		},
		{
			name: "delimatbeginning",
			c:    ".groups",
			d:    ".",
			err:  errors.New(`instance of "." delimiter in claim is at beginning of claim string`),
		},
		{
			name: "backtoback",
			c:    "gro/.ups",
			d:    "/.",
			err:  errors.New(`instance of "." delimiter in claim is at beginning of claim string`),
		},
	}

	for _, testCase := range testCases {
		ret, err := parseClaimWithDelimiters(testCase.c, testCase.d)
		if diff := deep.Equal(testCase.err, err); diff != nil {
			t.Fatalf("%s: %v", testCase.name, diff)
		}
		if diff := deep.Equal(testCase.res, ret); diff != nil {
			t.Fatalf("%s: %v", testCase.name, diff)
		}
	}
}
