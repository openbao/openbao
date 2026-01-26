// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/kr/pretty"
	"github.com/openbao/openbao/api/v2"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	"github.com/openbao/openbao/helper/testhelpers"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault"
)

// Tests the regression in
// https://github.com/openbao/openbao/builtin/logical/kv/pull/31
func TestKVv2_UpgradePaths(t *testing.T) {
	m := new(sync.Mutex)
	logOut := new(bytes.Buffer)

	logger := hclog.New(&hclog.LoggerOptions{
		Output: logOut,
		Mutex:  m,
	})

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": logicalKv.Factory,
		},
		EnableRaw: true,
		Logger:    logger,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0]
	vault.TestWaitActive(t, core.Core)
	client := core.Client

	// Enable KVv2
	err := client.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v2",
	})
	if err != nil {
		t.Fatal(err)
	}

	cluster.EnsureCoresSealed(t)

	ctx := context.Background()

	// Delete the policy from storage, to trigger the clean slate necessary for
	// the error
	mounts, err := core.UnderlyingRawStorage.List(ctx, "logical/")
	if err != nil {
		t.Fatal(err)
	}
	kvMount := mounts[0]
	basePaths, err := core.UnderlyingRawStorage.List(ctx, "logical/"+kvMount)
	if err != nil {
		t.Fatal(err)
	}
	basePath := basePaths[0]

	beforeList, err := core.UnderlyingRawStorage.List(ctx, "logical/"+kvMount+basePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(pretty.Sprint(beforeList))

	// Delete policy/archive
	if err = logical.ClearView(ctx, physical.NewView(core.UnderlyingRawStorage, "logical/"+kvMount+basePath+"policy/")); err != nil {
		t.Fatal(err)
	}
	if err = logical.ClearView(ctx, physical.NewView(core.UnderlyingRawStorage, "logical/"+kvMount+basePath+"archive/")); err != nil {
		t.Fatal(err)
	}

	afterList, err := core.UnderlyingRawStorage.List(ctx, "logical/"+kvMount+basePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(pretty.Sprint(afterList))

	testhelpers.EnsureCoresUnsealed(t, cluster)

	// Need to give it time to actually set up
	time.Sleep(10 * time.Second)

	m.Lock()
	defer m.Unlock()
	if strings.Contains(logOut.String(), "cannot write to storage during setup") {
		t.Fatal("got a cannot write to storage during setup error")
	}
}
