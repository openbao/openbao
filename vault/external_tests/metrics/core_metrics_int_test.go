// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/corehelpers"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/testhelpers"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/vault"
)

func TestMountTableMetrics(t *testing.T) {
	clusterName := "mycluster"
	conf := &vault.CoreConfig{
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		ClusterName:     clusterName,
	}
	cluster := vault.NewTestCluster(t, conf, &vault.TestClusterOptions{
		KeepStandbysSealed:     false,
		HandlerFunc:            vaulthttp.Handler,
		NumCores:               2,
		CoreMetricSinkProvider: testhelpers.TestMetricSinkProvider(time.Minute),
	})

	cluster.Start()
	defer cluster.Cleanup()

	// Wait for core to become active
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	// Verify that the nonlocal logical mount table has 3 entries -- cubbyhole, identity, and kv

	data, err := testhelpers.SysMetricsReq(client, cluster, false)
	if err != nil {
		t.Fatal(err)
	}

	nonlocalLogicalMountsize, err := gaugeSearchHelper(data, 3)
	if err != nil {
		t.Error(err.Error())
	}

	if nonlocalLogicalMountsize <= 0 {
		t.Fatalf("expected non-zero value for nonlocalLogicalMountsize: %v", nonlocalLogicalMountsize)
	}

	// Mount new kv
	if err = client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}); err != nil {
		t.Fatal(err)
	}

	data, err = testhelpers.SysMetricsReq(client, cluster, false)
	if err != nil {
		t.Fatal(err)
	}

	// Notably, the gauge only reports the size of the new table entry; it
	// does not report the total size on a transactional storage backend.
	nonlocalLogicalMountsizeAfterMount, err := gaugeSearchHelper(data, 4)
	if err != nil {
		t.Error(err.Error())
	}

	if nonlocalLogicalMountsizeAfterMount <= 0 {
		t.Fatalf("expected non-zero value for nonlocalLogicalMountsizeAfterMount: %v", nonlocalLogicalMountsizeAfterMount)
	}
}

func gaugeSearchHelper(data *testhelpers.SysMetricsJSON, expectedValue int) (int, error) {
	foundFlag := false
	tablesize := int(^uint(0) >> 1)
	for _, gauge := range data.Gauges {
		labels := gauge.Labels
		if loc, ok := labels["local"]; ok && loc.(string) == "false" {
			if tp, ok := labels["type"]; ok && tp.(string) == "logical" {
				switch gauge.Name {
				case "core.mount_table.num_entries":
					foundFlag = true
					if err := gaugeConditionCheck("eq", expectedValue, gauge.Value); err != nil {
						return int(^uint(0) >> 1), err
					}
				case "core.mount_table.size":
					tablesize = gauge.Value
				}
			}
		}
	}
	if !foundFlag {
		return int(^uint(0) >> 1), errors.New("No metrics reported for mount sizes")
	}
	return tablesize, nil
}

func gaugeConditionCheck(comparator string, compareVal int, compareToVal int) error {
	if comparator == "eq" && compareVal != compareToVal {
		return errors.New("equality gauge check for comparison failed")
	}
	return nil
}

func TestLeaderReElectionMetrics(t *testing.T) {
	clusterName := "mycluster"
	conf := &vault.CoreConfig{
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		ClusterName:     clusterName,
	}
	cluster := vault.NewTestCluster(t, conf, &vault.TestClusterOptions{
		KeepStandbysSealed:     false,
		HandlerFunc:            vaulthttp.Handler,
		NumCores:               2,
		CoreMetricSinkProvider: testhelpers.TestMetricSinkProvider(time.Minute),
	})

	cluster.Start()
	defer cluster.Cleanup()

	// Wait for core to become active
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client
	standbyClient := cores[1].Client

	r := client.NewRequest("GET", "/v1/sys/metrics")
	r2 := standbyClient.NewRequest("GET", "/v1/sys/metrics")
	r.Headers.Set("X-Vault-Token", cluster.RootToken)
	r2.Headers.Set("X-Vault-Token", cluster.RootToken)
	respo, err := client.RawRequestWithContext(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := io.ReadAll(respo.Body)
	if err != nil {
		t.Fatal(err)
	}
	if respo != nil {
		defer respo.Body.Close()
	}
	var data testhelpers.SysMetricsJSON
	coreLeaderMetric := false
	coreUnsealMetric := false
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		t.Fatal("failed to unmarshal:", err)
	}
	for _, gauge := range data.Gauges {
		if gauge.Name == "core.active" {
			coreLeaderMetric = true
			if gauge.Value != 1 {
				t.Error("metric incorrectly reports active status")
			}
		}
		if gauge.Name == "core.unsealed" {
			coreUnsealMetric = true
			if gauge.Value != 1 {
				t.Error("metric incorrectly reports unseal status of leader")
			}
		}
	}
	if !coreLeaderMetric || !coreUnsealMetric {
		t.Error("unseal metric or leader metric are missing")
	}

	err = client.Sys().StepDown()
	if err != nil {
		t.Fatal(err)
	}
	// Wait for core to become active
	vault.TestWaitActive(t, cores[1].Core)

	r = standbyClient.NewRequest("GET", "/v1/sys/metrics")
	r.Headers.Set("X-Vault-Token", cluster.RootToken)
	respo, err = standbyClient.RawRequestWithContext(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err = io.ReadAll(respo.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		t.Fatal("failed to unmarshal:", err)
	} else {
		coreLeaderMetric = false
		coreUnsealMetric = false
		for _, gauge := range data.Gauges {
			if gauge.Name == "core.active" {
				coreLeaderMetric = true
				if gauge.Value != 1 {
					t.Error("metric incorrectly reports active status")
				}
			}
			if gauge.Name == "core.unsealed" {
				coreUnsealMetric = true
				if gauge.Value != 1 {
					t.Error("metric incorrectly reports unseal status of leader")
				}
			}
		}
		if !coreLeaderMetric || !coreUnsealMetric {
			t.Error("unseal metric or leader metric are missing")
		}
	}
	if respo != nil {
		defer respo.Body.Close()
	}
}
