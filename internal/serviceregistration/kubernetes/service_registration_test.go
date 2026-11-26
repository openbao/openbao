// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	sr "github.com/openbao/openbao/v2/internal/serviceregistration"
	"github.com/openbao/openbao/v2/internal/serviceregistration/kubernetes/client"
	kubetest "github.com/openbao/openbao/v2/internal/serviceregistration/kubernetes/testing"
	"github.com/stretchr/testify/require"
)

var testVersion = "version1"

func TestServiceRegistration(t *testing.T) {
	testState, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	require.NoError(t, os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost))
	require.NoError(t, os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort))

	if testState.NumPatches() != 0 {
		t.Fatalf("expected 0 patches but have %d: %+v", testState.NumPatches(), testState)
	}
	shutdownCh := make(chan struct{})
	config := map[string]string{
		"namespace": kubetest.ExpectedNamespace,
		"pod_name":  kubetest.ExpectedPodName,
	}
	logger := hclog.NewNullLogger()
	state := sr.State{
		VaultVersion:         testVersion,
		IsInitialized:        true,
		IsSealed:             true,
		IsActive:             true,
		IsPerformanceStandby: true,
	}
	reg, err := NewServiceRegistration(config, logger, state)
	require.NoError(t, err)
	require.NoError(t, reg.Run(shutdownCh, &sync.WaitGroup{}, ""))

	// Test initial state.
	if testState.NumPatches() != 5 {
		t.Fatalf("expected 5 current labels but have %d: %+v", testState.NumPatches(), testState)
	}
	if testState.Get(pathToLabels + labelVaultVersion)["value"] != testVersion {
		t.Fatalf("expected %q but received %q", testVersion, testState.Get(pathToLabels + labelVaultVersion)["value"])
	}
	if testState.Get(pathToLabels + labelActive)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelActive)["value"])
	}
	if testState.Get(pathToLabels + labelSealed)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelSealed)["value"])
	}
	if testState.Get(pathToLabels + labelPerfStandby)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelPerfStandby)["value"])
	}
	if testState.Get(pathToLabels + labelInitialized)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelInitialized)["value"])
	}

	// Test NotifyActiveStateChange.
	require.NoError(t, reg.NotifyActiveStateChange(false))
	if testState.Get(pathToLabels + labelActive)["value"] != strconv.FormatBool(false) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(false), testState.Get(pathToLabels + labelActive)["value"])
	}
	require.NoError(t, reg.NotifyActiveStateChange(true))
	if testState.Get(pathToLabels + labelActive)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelActive)["value"])
	}

	// Test NotifySealedStateChange.
	require.NoError(t, reg.NotifySealedStateChange(false))
	if testState.Get(pathToLabels + labelSealed)["value"] != strconv.FormatBool(false) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(false), testState.Get(pathToLabels + labelSealed)["value"])
	}
	require.NoError(t, reg.NotifySealedStateChange(true))
	if testState.Get(pathToLabels + labelSealed)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelSealed)["value"])
	}

	// Test NotifyPerformanceStandbyStateChange.
	require.NoError(t, reg.NotifyPerformanceStandbyStateChange(false))
	if testState.Get(pathToLabels + labelPerfStandby)["value"] != strconv.FormatBool(false) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(false), testState.Get(pathToLabels + labelPerfStandby)["value"])
	}
	require.NoError(t, reg.NotifyPerformanceStandbyStateChange(true))
	if testState.Get(pathToLabels + labelPerfStandby)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelPerfStandby)["value"])
	}

	// Test NotifyInitializedStateChange.
	require.NoError(t, reg.NotifyInitializedStateChange(false))
	if testState.Get(pathToLabels + labelInitialized)["value"] != strconv.FormatBool(false) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(false), testState.Get(pathToLabels + labelInitialized)["value"])
	}
	require.NoError(t, reg.NotifyInitializedStateChange(true))
	if testState.Get(pathToLabels + labelInitialized)["value"] != strconv.FormatBool(true) {
		t.Fatalf("expected %q but received %q", strconv.FormatBool(true), testState.Get(pathToLabels + labelInitialized)["value"])
	}
}
