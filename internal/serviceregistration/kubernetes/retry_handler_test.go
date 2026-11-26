// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	sr "github.com/openbao/openbao/v2/internal/serviceregistration"
	"github.com/openbao/openbao/v2/internal/serviceregistration/kubernetes/client"
	kubetest "github.com/openbao/openbao/v2/internal/serviceregistration/kubernetes/testing"
	"github.com/stretchr/testify/require"
)

func TestRetryHandlerSimple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping because this test takes 10-15 seconds")
	}

	testState, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	if err := os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	logger := hclog.NewNullLogger()
	shutdownCh := make(chan struct{})
	wait := &sync.WaitGroup{}

	c, err := client.New(logger)
	require.NoError(t, err)

	r := &retryHandler{
		logger:         logger,
		namespace:      kubetest.ExpectedNamespace,
		podName:        kubetest.ExpectedPodName,
		patchesToRetry: make(map[string]*client.Patch),
		client:         c,
		initialState:   sr.State{},
	}
	r.Run(shutdownCh, wait)
	t.Cleanup(func() {
		close(shutdownCh)
		wait.Wait()
	})

	// Initial number of patches upon Run from setting the initial state
	require.Eventually(t, func() bool {
		return testState.NumPatches() > 0
	}, 5*time.Second, 10*time.Millisecond)
	initStatePatches := testState.NumPatches()

	// Send a new patch
	testPatch := &client.Patch{
		Operation: client.Add,
		Path:      "patch-path",
		Value:     "true",
	}
	r.Notify(testPatch)

	// Wait ample until the next try should have occurred.
	<-time.NewTimer(retryFreq * 2).C

	if testState.NumPatches() != initStatePatches+1 {
		t.Fatalf("expected 1 patch, got: %d", testState.NumPatches())
	}
}

func TestRetryHandlerAdd(t *testing.T) {
	_, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	if err := os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	logger := hclog.NewNullLogger()
	c, err := client.New(logger)
	require.NoError(t, err)

	r := &retryHandler{
		logger:         hclog.NewNullLogger(),
		namespace:      "some-namespace",
		podName:        "some-pod-name",
		patchesToRetry: make(map[string]*client.Patch),
		client:         c,
	}

	testPatch1 := &client.Patch{
		Operation: client.Add,
		Path:      "one",
		Value:     "true",
	}
	testPatch2 := &client.Patch{
		Operation: client.Add,
		Path:      "two",
		Value:     "true",
	}
	testPatch3 := &client.Patch{
		Operation: client.Add,
		Path:      "three",
		Value:     "true",
	}
	testPatch4 := &client.Patch{
		Operation: client.Add,
		Path:      "four",
		Value:     "true",
	}

	// Should be able to add all 4 patches.
	r.Notify(testPatch1)
	if len(r.patchesToRetry) != 1 {
		t.Fatal("expected 1 patch")
	}

	r.Notify(testPatch2)
	if len(r.patchesToRetry) != 2 {
		t.Fatal("expected 2 patches")
	}

	r.Notify(testPatch3)
	if len(r.patchesToRetry) != 3 {
		t.Fatal("expected 3 patches")
	}

	r.Notify(testPatch4)
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}

	// Adding a dupe should result in no change.
	r.Notify(testPatch4)
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}

	// Adding a reversion should result in its twin being subtracted.
	r.Notify(&client.Patch{
		Operation: client.Add,
		Path:      "four",
		Value:     "false",
	})
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}

	r.Notify(&client.Patch{
		Operation: client.Add,
		Path:      "three",
		Value:     "false",
	})
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}

	r.Notify(&client.Patch{
		Operation: client.Add,
		Path:      "two",
		Value:     "false",
	})
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}

	r.Notify(&client.Patch{
		Operation: client.Add,
		Path:      "one",
		Value:     "false",
	})
	if len(r.patchesToRetry) != 4 {
		t.Fatal("expected 4 patches")
	}
}

// This is meant to be run with the -race flag on.
func TestRetryHandlerRacesAndDeadlocks(t *testing.T) {
	_, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	if err := os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	logger := hclog.NewNullLogger()
	shutdownCh := make(chan struct{})
	wait := &sync.WaitGroup{}
	testPatch := &client.Patch{
		Operation: client.Add,
		Path:      "patch-path",
		Value:     "true",
	}

	c, err := client.New(logger)
	require.NoError(t, err)

	r := &retryHandler{
		logger:         logger,
		namespace:      kubetest.ExpectedNamespace,
		podName:        kubetest.ExpectedPodName,
		patchesToRetry: make(map[string]*client.Patch),
		initialState:   sr.State{},
		client:         c,
	}

	// Now hit it as quickly as possible to see if we can produce
	// races or deadlocks.
	start := make(chan struct{})
	done := make(chan bool)
	numRoutines := 100
	for range numRoutines {
		go func() {
			<-start
			r.Notify(testPatch)
			done <- true
		}()
		go func() {
			<-start
			r.Run(shutdownCh, wait)
			done <- true
		}()
	}
	close(start)

	// Allow up to 5 seconds for everything to finish.
	timer := time.NewTimer(5 * time.Second)
	for i := 0; i < numRoutines*2; i++ {
		select {
		case <-timer.C:
			t.Fatal("test took too long to complete, check for deadlock")
		case <-done:
		}
	}
}

// In this test, the API server sends bad responses for 5 seconds,
// then sends good responses, and we make sure we get the expected behavior.
func TestRetryHandlerAPIConnectivityProblemsInitialState(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	testState, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()
	kubetest.ReturnGatewayTimeouts.Store(true)

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	client.RetryMax = 0
	if err := os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	shutdownCh := make(chan struct{})
	wait := &sync.WaitGroup{}
	reg, err := NewServiceRegistration(map[string]string{
		"namespace": kubetest.ExpectedNamespace,
		"pod_name":  kubetest.ExpectedPodName,
	}, hclog.NewNullLogger(), sr.State{
		VaultVersion:         "vault-version",
		IsInitialized:        true,
		IsSealed:             true,
		IsActive:             true,
		IsPerformanceStandby: true,
	})
	require.NoError(t, err)
	if err := reg.Run(shutdownCh, wait, ""); err != nil {
		t.Fatal(err)
	}

	// At this point, since the initial state can't be set,
	// remotely we should have false for all these labels.
	patch := testState.Get(pathToLabels + labelVaultVersion)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelActive)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelSealed)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelPerfStandby)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelInitialized)
	if patch != nil {
		t.Fatal("expected no value")
	}

	kubetest.ReturnGatewayTimeouts.Store(false)

	// Now we need to wait to give the retry handler
	// a chance to update these values.
	time.Sleep(retryFreq + time.Second)
	val := testState.Get(pathToLabels + labelVaultVersion)["value"]
	if val != "vault-version" {
		t.Fatal("expected vault-version")
	}
	val = testState.Get(pathToLabels + labelActive)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelSealed)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelPerfStandby)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelInitialized)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
}

// In this test, the API server sends bad responses for 5 seconds,
// then sends good responses, and we make sure we get the expected behavior.
func TestRetryHandlerAPIConnectivityProblemsNotifications(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	testState, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()
	kubetest.ReturnGatewayTimeouts.Store(true)

	client.Scheme = testConf.ClientScheme
	client.TokenFile = testConf.PathToTokenFile
	client.RootCAFile = testConf.PathToRootCAFile
	client.RetryMax = 0
	if err := os.Setenv(client.EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(client.EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	shutdownCh := make(chan struct{})
	wait := &sync.WaitGroup{}
	reg, err := NewServiceRegistration(map[string]string{
		"namespace": kubetest.ExpectedNamespace,
		"pod_name":  kubetest.ExpectedPodName,
	}, hclog.NewNullLogger(), sr.State{
		VaultVersion:         "vault-version",
		IsInitialized:        false,
		IsSealed:             false,
		IsActive:             false,
		IsPerformanceStandby: false,
	})
	require.NoError(t, err)

	if err := reg.NotifyActiveStateChange(true); err != nil {
		t.Fatal(err)
	}
	if err := reg.NotifyInitializedStateChange(true); err != nil {
		t.Fatal(err)
	}
	if err := reg.NotifyPerformanceStandbyStateChange(true); err != nil {
		t.Fatal(err)
	}
	if err := reg.NotifySealedStateChange(true); err != nil {
		t.Fatal(err)
	}

	if err := reg.Run(shutdownCh, wait, ""); err != nil {
		t.Fatal(err)
	}

	// At this point, since the initial state can't be set,
	// remotely we should have false for all these labels.
	patch := testState.Get(pathToLabels + labelVaultVersion)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelActive)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelSealed)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelPerfStandby)
	if patch != nil {
		t.Fatal("expected no value")
	}
	patch = testState.Get(pathToLabels + labelInitialized)
	if patch != nil {
		t.Fatal("expected no value")
	}

	kubetest.ReturnGatewayTimeouts.Store(false)

	// Now we need to wait to give the retry handler
	// a chance to update these values.
	time.Sleep(retryFreq + time.Second)

	// They should be "true" if the Notifications were set after the
	// initial state.
	val := testState.Get(pathToLabels + labelVaultVersion)["value"]
	if val != "vault-version" {
		t.Fatal("expected vault-version")
	}
	val = testState.Get(pathToLabels + labelActive)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelSealed)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelPerfStandby)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
	val = testState.Get(pathToLabels + labelInitialized)["value"]
	if val != "true" {
		t.Fatal("expected true")
	}
}

func TestServiceRegistration_UnreachableAPIDoesNotBlockRunOrShutdown(t *testing.T) {
	var hits atomic.Int32
	unblock := make(chan struct{})
	defer close(unblock)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-unblock:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	dir := t.TempDir()
	tokFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokFile, []byte("test-token"), 0o600))
	caFile := dir + "/ca.crt"
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	origScheme, origToken, origCA := client.Scheme, client.TokenFile, client.RootCAFile
	origWaitMin, origWaitMax, origRetries := client.RetryWaitMin, client.RetryWaitMax, client.RetryMax
	t.Cleanup(func() {
		client.Scheme, client.TokenFile, client.RootCAFile = origScheme, origToken, origCA
		client.RetryWaitMin, client.RetryWaitMax, client.RetryMax = origWaitMin, origWaitMax, origRetries
	})
	client.Scheme = u.Scheme + "://"
	client.TokenFile = tokFile
	client.RootCAFile = caFile
	client.RetryWaitMin = 5 * time.Second
	client.RetryWaitMax = 10 * time.Second
	client.RetryMax = 10
	t.Setenv(client.EnvVarKubernetesServiceHost, u.Hostname())
	t.Setenv(client.EnvVarKubernetesServicePort, u.Port())

	reg, err := NewServiceRegistration(map[string]string{
		"namespace": "default",
		"pod_name":  "openbao-0",
	}, hclog.NewNullLogger(), sr.State{VaultVersion: "2.7.3"})
	require.NoError(t, err)

	shutdownCh := make(chan struct{})
	wait := &sync.WaitGroup{}

	start := time.Now()
	require.NoError(t, reg.Run(shutdownCh, wait, ""))
	require.Less(t, time.Since(start), 500*time.Millisecond, "Run must not block on unreachable Kubernetes API")

	require.Eventually(t, func() bool {
		return hits.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	close(shutdownCh)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("service registration did not shut down promptly")
	}
}
