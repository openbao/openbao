// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	kubetest "github.com/openbao/openbao/v2/internal/serviceregistration/kubernetes/testing"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	testState, testConf, closeFunc := kubetest.Server(t)
	defer closeFunc()

	Scheme = testConf.ClientScheme
	TokenFile = testConf.PathToTokenFile
	RootCAFile = testConf.PathToRootCAFile
	if err := os.Setenv(EnvVarKubernetesServiceHost, testConf.ServiceHost); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(EnvVarKubernetesServicePort, testConf.ServicePort); err != nil {
		t.Fatal(err)
	}

	client, err := New(hclog.Default())
	require.NoError(t, err)
	e := &env{
		client:    client,
		testState: testState,
	}
	e.TestGetPod(t)
	e.TestGetPodNotFound(t)
	e.TestUpdatePodTags(t)
	e.TestUpdatePodTagsNotFound(t)
}

type env struct {
	client    *Client
	testState *kubetest.State
}

func (e *env) TestGetPod(t *testing.T) {
	pod, err := e.client.GetPod(kubetest.ExpectedNamespace, kubetest.ExpectedPodName)
	require.NoError(t, err)
	if pod.Metadata.Name != "shell-demo" {
		t.Fatalf("expected %q but received %q", "shell-demo", pod.Metadata.Name)
	}
}

func (e *env) TestGetPodNotFound(t *testing.T) {
	_, err := e.client.GetPod(kubetest.ExpectedNamespace, "no-exist")
	if err == nil {
		t.Fatal("expected error because pod is unfound")
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		err = wrapped
	}
	if _, ok := err.(*ErrNotFound); !ok {
		t.Fatalf("expected *ErrNotFound but received %T (%s)", err, err)
	}
}

func (e *env) TestUpdatePodTags(t *testing.T) {
	if err := e.client.PatchPod(kubetest.ExpectedNamespace, kubetest.ExpectedPodName, &Patch{
		Operation: Add,
		Path:      "/metadata/labels/fizz",
		Value:     "buzz",
	}); err != nil {
		t.Fatal(err)
	}
	if e.testState.NumPatches() != 1 {
		t.Fatalf("expected 1 label but received %+v", e.testState)
	}
	if e.testState.Get("/metadata/labels/fizz")["value"] != "buzz" {
		t.Fatalf("expected buzz but received %q", e.testState.Get("fizz")["value"])
	}
	if e.testState.Get("/metadata/labels/fizz")["op"] != "add" {
		t.Fatalf("expected add but received %q", e.testState.Get("fizz")["op"])
	}
}

func (e *env) TestUpdatePodTagsNotFound(t *testing.T) {
	err := e.client.PatchPod(kubetest.ExpectedNamespace, "no-exist", &Patch{
		Operation: Add,
		Path:      "/metadata/labels/fizz",
		Value:     "buzz",
	})
	if err == nil {
		t.Fatal("expected error because pod is unfound")
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		err = wrapped
	}
	if _, ok := err.(*ErrNotFound); !ok {
		t.Fatalf("expected *ErrNotFound but received %T", err)
	}
}

func TestSanitize(t *testing.T) {
	expected := "fizz-buzz"
	result := Sanitize("fizz+buzz")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}

	expected = "fizz_buzz"
	result = Sanitize("fizz_buzz")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}

	expected = "fizz.buzz"
	result = Sanitize("fizz.buzz")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}

	expected = "fizz-buzz"
	result = Sanitize("fizz-buzz")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}

	expected = "123--fhd"
	result = Sanitize("123-*fhd")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}

	expected = "1.4.0-beta1-ent"
	result = Sanitize("1.4.0-beta1+ent")
	if result != expected {
		t.Fatalf("expected %q but received %q", expected, result)
	}
}

func setupClientTestEnv(t *testing.T, srv *httptest.Server) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	dir := t.TempDir()
	tokFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokFile, []byte("test-token"), 0o600))
	caFile := dir + "/ca.crt"
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	origScheme, origToken, origCA := Scheme, TokenFile, RootCAFile
	t.Cleanup(func() {
		Scheme, TokenFile, RootCAFile = origScheme, origToken, origCA
	})
	Scheme = u.Scheme + "://"
	TokenFile = tokFile
	RootCAFile = caFile

	t.Setenv(EnvVarKubernetesServiceHost, u.Hostname())
	t.Setenv(EnvVarKubernetesServicePort, u.Port())
}

func TestClient_ShutdownCancelsRetriesImmediately(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	setupClientTestEnv(t, srv)

	origMin, origMax, origRetries := RetryWaitMin, RetryWaitMax, RetryMax
	t.Cleanup(func() {
		RetryWaitMin, RetryWaitMax, RetryMax = origMin, origMax, origRetries
	})
	RetryWaitMin = 5 * time.Second
	RetryWaitMax = 10 * time.Second
	RetryMax = 5

	c, err := New(hclog.NewNullLogger())
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, err := c.GetPod("default", "openbao-0")
		errCh <- err
	}()

	require.Eventually(t, func() bool {
		return attempts.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	c.Shutdown()

	select {
	case err := <-errCh:
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("GetPod did not stop promptly after Shutdown()")
	}
}

func TestClient_SlowResponseTimesOut(t *testing.T) {
	unblock := make(chan struct{})
	defer close(unblock)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-unblock:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	setupClientTestEnv(t, srv)

	origReqTO, origHdrTO := DefaultRequestTimeout, DefaultResponseHeaderTimeout
	origRetries := RetryMax
	t.Cleanup(func() {
		DefaultRequestTimeout = origReqTO
		DefaultResponseHeaderTimeout = origHdrTO
		RetryMax = origRetries
	})
	DefaultRequestTimeout = 150 * time.Millisecond
	DefaultResponseHeaderTimeout = 100 * time.Millisecond
	RetryMax = 0

	c, err := New(hclog.NewNullLogger())
	require.NoError(t, err)
	defer c.Shutdown()

	start := time.Now()
	_, err = c.GetPod("default", "openbao-0")
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
}
