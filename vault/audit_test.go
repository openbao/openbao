// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/logical"
	auditCore "github.com/openbao/openbao/vault/audit"
	"github.com/openbao/openbao/vault/routing"
)

func TestAudit_ReadOnlyViewDuringMount(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		err := config.SaltView.Put(ctx, &logical.StorageEntry{
			Key:   "bar",
			Value: []byte("baz"),
		})
		if err == nil || !strings.Contains(err.Error(), logical.ErrSetupReadOnly.Error()) {
			t.Fatal("expected a read-only error")
		}
		factory := corehelpers.NoopAuditFactory(nil)
		return factory(ctx, config)
	}

	me := &routing.MountEntry{
		Table: auditCore.TableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.audit.EnableAudit(namespace.RootContext(t.Context()), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestCore_EnableAudit(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)

	me := &routing.MountEntry{
		Table: auditCore.TableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.audit.EnableAudit(namespace.RootContext(t.Context()), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !c.audit.Broker.IsRegistered("foo/") {
		t.Fatal("missing audit backend")
	}

	conf := &CoreConfig{
		Physical:      c.physical,
		AuditBackends: make(map[string]audit.Factory),
	}
	conf.AuditBackends["noop"] = corehelpers.NoopAuditFactory(nil)
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching audit tables
	if !reflect.DeepEqual(c.audit.Mt, c2.audit.Mt) {
		t.Fatalf("mismatch: %v %v", c.audit.Mt, c2.audit.Mt)
	}

	// Check for registration
	if !c2.audit.Broker.IsRegistered("foo/") {
		t.Fatal("missing audit backend")
	}
}

func TestCore_DisableAudit(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)

	existed, err := c.audit.DisableAudit(namespace.RootContext(t.Context()), "foo", true)
	if existed && err != nil {
		t.Fatalf("existed: %v; err: %v", existed, err)
	}

	me := &routing.MountEntry{
		Table: auditCore.TableType,
		Path:  "foo",
		Type:  "noop",
	}
	err = c.audit.EnableAudit(namespace.RootContext(t.Context()), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	existed, err = c.audit.DisableAudit(namespace.RootContext(t.Context()), "foo", true)
	if !existed || err != nil {
		t.Fatalf("existed: %v; err: %v", existed, err)
	}

	// Check for registration
	if c.audit.Broker.IsRegistered("foo") {
		t.Fatal("audit backend present")
	}

	conf := &CoreConfig{
		Physical: c.physical,
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if !reflect.DeepEqual(c.audit.Mt, c2.audit.Mt) {
		t.Fatalf("mismatch:\n%#v\n%#v", c.audit.Mt, c2.audit.Mt)
	}
}

func TestCore_DefaultAuditTable(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)

	// Verify we have an audit broker
	if c.audit.Broker == nil {
		t.Fatal("missing audit broker")
	}

	// Start a second core with same physical
	conf := &CoreConfig{
		Physical: c.physical,
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if !reflect.DeepEqual(c.audit.Mt, c2.audit.Mt) {
		t.Fatalf("mismatch: %v %v", c.audit.Mt, c2.audit.Mt)
	}
}
