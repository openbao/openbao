// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/hostutil"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestSysHostInfo(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	// Query against the active node, should get host information back
	secret, err := cores[0].Client.Logical().Read("sys/host-info")
	require.NoError(t, err)
	if secret == nil || secret.Data == nil {
		t.Fatal("expected data in the response")
	}

	dataBytes, err := json.Marshal(secret.Data)
	require.NoError(t, err)

	var infoActive hostutil.HostInfo
	if err := json.Unmarshal(dataBytes, &infoActive); err != nil {
		t.Fatal(err)
	}

	if infoActive.Timestamp.IsZero() {
		t.Fatal("expected non-zero Timestamp")
	}
	if infoActive.CPU == nil {
		t.Fatal("expected non-nil CPU value")
	}
	if infoActive.Disk == nil {
		t.Fatal("expected disk info")
	}
	if infoActive.Host == nil {
		t.Fatal("expected host info")
	}
	if infoActive.Memory == nil {
		t.Fatal("expected memory info")
	}

	// Query against a standby, should not error and request should be forwarded to active
	secret, err = cores[1].Client.Logical().Read("sys/host-info")
	require.NoError(t, err)
	if secret == nil || secret.Data == nil {
		t.Fatal("expected data in the response")
	}

	dataBytes, err = json.Marshal(secret.Data)
	require.NoError(t, err)

	var infoStandby hostutil.HostInfo
	if err := json.Unmarshal(dataBytes, &infoStandby); err != nil {
		t.Fatal(err)
	}

	if infoStandby.Host.Hostname != infoActive.Host.Hostname {
		t.Fatal("request should be answered by active (standby forwarded)")
	}
}
