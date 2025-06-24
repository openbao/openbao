// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"reflect"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
)

// TestDefaultSeal_Config exercises Shamir SetBarrierConfig and BarrierConfig.
// Note that this is a little questionable, because we're doing an init and
// unseal, then changing the barrier config using an internal function instead
// of an API. In other words if your change break this test, it might be more
// the test's fault than your changes.
func TestDefaultSeal_Config(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    4,
		SecretThreshold: 2,
	}
	core, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())

	defSeal := NewDefaultSeal(nil)
	defSeal.SetCore(core)
	err := defSeal.SetConfig(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}

	newBc, err := defSeal.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*bc, *newBc) {
		t.Fatal("config mismatch")
	}

	// Now, test without the benefit of the cached value in the seal
	defSeal = NewDefaultSeal(nil)
	defSeal.SetCore(core)
	newBc, err = defSeal.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*bc, *newBc) {
		t.Fatal("config mismatch")
	}

	nsSealConfig := &SealConfig{
		SecretShares:    10,
		SecretThreshold: 5,
	}

	nsTest := &namespace.Namespace{Path: "test/"}
	TestCoreCreateNamespaces(t, core, nsTest)

	nsCtx := namespace.ContextWithNamespace(ctx, nsTest)
	defSeal = NewDefaultSeal(nil)
	defSeal.SetCore(core)
	err = defSeal.SetConfig(nsCtx, nsSealConfig)
	if err != nil {
		t.Fatal(err)
	}

	newNSSealConfig, err := defSeal.Config(nsCtx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*nsSealConfig, *newNSSealConfig) {
		t.Fatal("config mismatch")
	}

	// Now, test without the benefit of the cached value in the seal
	defSeal = NewDefaultSeal(nil)
	defSeal.SetCore(core)
	newNSSealConfig, err = defSeal.Config(nsCtx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*nsSealConfig, *newNSSealConfig) {
		t.Fatal("config mismatch")
	}
}
