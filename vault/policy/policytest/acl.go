package policytest

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/policy"
)

func TestLayeredACL(t *testing.T, acl *policy.ACL, ns *namespace.Namespace) {
	// Type of operation is not important here as we only care about checking
	// sudo/root
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	request := new(logical.Request)
	request.Operation = logical.ReadOperation
	request.Path = "sys/mount/foo"

	authResults := acl.AllowOperation(ctx, request, false)
	if authResults.RootPrivs {
		t.Fatal("unexpected root")
	}

	type tcase struct {
		op        logical.Operation
		path      string
		allowed   bool
		rootPrivs bool
	}
	tcases := []tcase{
		{logical.ReadOperation, "root", false, false},
		{logical.HelpOperation, "root", true, false},

		{logical.ReadOperation, "dev/foo", true, true},
		{logical.UpdateOperation, "dev/foo", true, true},
		{logical.ReadOperation, "dev/hide/foo", false, false},
		{logical.UpdateOperation, "dev/hide/foo", false, false},

		{logical.DeleteOperation, "stage/foo", true, false},
		{logical.ListOperation, "stage/aws/foo", true, true},
		{logical.UpdateOperation, "stage/aws/foo", true, true},
		{logical.UpdateOperation, "stage/aws/policy/foo", false, false},

		{logical.DeleteOperation, "prod/foo", true, false},
		{logical.UpdateOperation, "prod/foo", true, false},
		{logical.ReadOperation, "prod/foo", true, false},
		{logical.ListOperation, "prod/foo", true, false},
		{logical.ReadOperation, "prod/aws/foo", false, false},

		{logical.ReadOperation, "sys/status", false, false},
		{logical.UpdateOperation, "sys/seal", true, true},

		{logical.ReadOperation, "foo/bar", false, false},
		{logical.ListOperation, "foo/bar", false, false},
		{logical.UpdateOperation, "foo/bar", false, false},
		{logical.CreateOperation, "foo/bar", false, false},

		{logical.ReadOperation, "baz/quux", false, false},
		{logical.ListOperation, "baz/quux", false, false},
		{logical.UpdateOperation, "baz/quux", false, false},
		{logical.CreateOperation, "baz/quux", false, false},
		{logical.PatchOperation, "baz/quux", false, false},
	}

	for _, tc := range tcases {
		ctx := namespace.ContextWithNamespace(context.Background(), ns)
		request := new(logical.Request)
		request.Operation = tc.op
		request.Path = tc.path

		authResults := acl.AllowOperation(ctx, request, false)
		if authResults.Allowed != tc.allowed {
			t.Fatalf("bad: case %#v: %v, %v", tc, authResults.Allowed, authResults.RootPrivs)
		}
		if authResults.RootPrivs != tc.rootPrivs {
			t.Fatalf("bad: case %#v: %v, %v", tc, authResults.Allowed, authResults.RootPrivs)
		}
	}
}

var ACLPolicy = `
name = "DeV"
path "dev/*" {
	policy = "sudo"
}
path "stage/*" {
	policy = "write"
}
path "stage/aws/*" {
	policy = "read"
	capabilities = ["update", "sudo"]
}
path "stage/aws/policy/*" {
	policy = "sudo"
}
path "prod/*" {
	policy = "read"
}
path "prod/aws/*" {
	policy = "deny"
}
path "sys/*" {
	policy = "deny"
}
path "foo/bar" {
	capabilities = ["read", "create", "sudo"]
}
path "baz/quux" {
	capabilities = ["read", "create", "patch"]
}
path "test/+/segment" {
	capabilities = ["read"]
}
path "+/segment/at/front" {
	capabilities = ["read"]
}
path "test/segment/at/end/+" {
	capabilities = ["read"]
}
path "test/segment/at/end/v2/+/" {
	capabilities = ["read"]
}
path "test/+/wildcard/+/*" {
	capabilities = ["read"]
}
path "test/+/wildcardglob/+/end*" {
	capabilities = ["read"]
}
path "1/2/*" {
	capabilities = ["create"]
}
path "1/2/+" {
	capabilities = ["read"]
}
path "1/2/+/+" {
	capabilities = ["update"]
}
path "asdf/fdsa" {
	capabilities = ["scan"]
}
`

var ACLPolicy2 = `
name = "OpS"
path "dev/hide/*" {
	policy = "deny"
}
path "stage/aws/policy/*" {
	policy = "deny"
	# This should have no effect
	capabilities = ["read", "update", "sudo"]
}
path "prod/*" {
	policy = "write"
}
path "sys/seal" {
	policy = "sudo"
}
path "foo/bar" {
	capabilities = ["deny"]
}
path "baz/quux" {
	capabilities = ["deny"]
}
`

var TokenCreationPolicy = `
name = "tokenCreation"
path "auth/token/create*" {
	capabilities = ["update", "create", "sudo"]
}
`
