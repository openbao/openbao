// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/corehelpers"

	"github.com/armon/go-metrics"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/vault"
)

func TestSysMetricsUnauthenticated(t *testing.T) {
	inm := metrics.NewInmemSink(10*time.Second, time.Minute)
	metrics.DefaultInmemSignal(inm)
	conf := &vault.CoreConfig{
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricsHelper:   metricsutil.NewMetricsHelper(inm, true),
	}
	core, _, token := vault.TestCoreUnsealedWithConfig(t, conf)
	ln, addr := TestServer(t, core)
	TestServerAuth(t, addr, token)

	// Default: Only authenticated access
	resp := testHttpGet(t, "", addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 403)
	resp = testHttpGet(t, token, addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 200)

	// Close listener
	ln.Close()

	// Setup new custom listener with unauthenticated metrics access
	ln, addr = TestListener(t)
	props := &vault.HandlerProperties{
		Core: core,
		ListenerConfig: &configutil.Listener{
			Telemetry: configutil.ListenerTelemetry{
				UnauthenticatedMetricsAccess: true,
			},
		},
	}
	TestServerWithListenerAndProperties(t, ln, addr, core, props)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	// Test without token
	resp = testHttpGet(t, "", addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 200)

	// Should also work with token
	resp = testHttpGet(t, token, addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 200)

	// Test if prometheus response is correct
	resp = testHttpGet(t, "", addr+"/v1/sys/metrics?format=prometheus")
	testResponseStatus(t, resp, 200)
}

func TestSysPProfUnauthenticated(t *testing.T) {
	conf := &vault.CoreConfig{}
	core, _, token := vault.TestCoreUnsealedWithConfig(t, conf)
	ln, addr := TestServer(t, core)
	TestServerAuth(t, addr, token)

	// Default: Only authenticated access
	resp := testHttpGet(t, "", addr+"/v1/sys/pprof/cmdline")
	testResponseStatus(t, resp, 403)
	resp = testHttpGet(t, token, addr+"/v1/sys/pprof/cmdline")
	testResponseStatus(t, resp, 200)

	// Close listener
	ln.Close()

	// Setup new custom listener with unauthenticated metrics access
	ln, addr = TestListener(t)
	props := &vault.HandlerProperties{
		Core: core,
		ListenerConfig: &configutil.Listener{
			Profiling: configutil.ListenerProfiling{
				UnauthenticatedPProfAccess: true,
			},
		},
	}
	TestServerWithListenerAndProperties(t, ln, addr, core, props)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	// Test without token
	resp = testHttpGet(t, "", addr+"/v1/sys/pprof/cmdline")
	testResponseStatus(t, resp, 200)

	// Should also work with token
	resp = testHttpGet(t, token, addr+"/v1/sys/pprof/cmdline")
	testResponseStatus(t, resp, 200)
}

// TestSysRekeyUnauthenticated ensures that unauthenticated endpoints are
// protected.
func TestSysRekeyUnauthenticated(t *testing.T) {
	conf := &vault.CoreConfig{}
	core, _, token := vault.TestCoreUnsealedWithConfig(t, conf)
	ln, addr := TestServer(t, core)
	TestServerAuth(t, addr, token)

	// Default: Allow unauthenticated access
	resp := testHttpGet(t, "", addr+"/v1/sys/rekey/init")
	testResponseStatus(t, resp, 200)
	resp = testHttpGet(t, token, addr+"/v1/sys/rekey/init")
	testResponseStatus(t, resp, 200)

	// Close listener
	ln.Close()

	// Setup new custom listener denying unauthenticated rekey access
	ln, addr = TestListener(t)
	props := &vault.HandlerProperties{
		Core: core,
		ListenerConfig: &configutil.Listener{
			DisableUnauthedRekeyEndpoints: true,
		},
	}
	TestServerWithListenerAndProperties(t, ln, addr, core, props)
	defer ln.Close()
	TestServerAuth(t, addr, token)

	// Testing with and without token should fail; we have completely removed
	// the endpoint.
	resp = testHttpGet(t, "", addr+"/v1/sys/rekey/init")
	testResponseStatus(t, resp, 405)
	resp = testHttpGet(t, token, addr+"/v1/sys/rekey/init")
	testResponseStatus(t, resp, 405)
}

func TestSysMetricsCustomPath(t *testing.T) {
	inm := metrics.NewInmemSink(10*time.Second, time.Minute)
	metrics.DefaultInmemSignal(inm)
	conf := &vault.CoreConfig{
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricsHelper:   metricsutil.NewMetricsHelper(inm, true),
	}
	core, _, token := vault.TestCoreUnsealedWithConfig(t, conf)
	ln, addr := TestServer(t, core)
	TestServerAuth(t, addr, token)

	// Default: Only authenticated access on standard path.
	resp := testHttpGet(t, "", addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 403)
	resp = testHttpGet(t, token, addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 200)

	resp = testHttpGet(t, "", addr+"/metrics")
	testResponseStatus(t, resp, 404)
	resp = testHttpGet(t, token, addr+"/metrics")
	testResponseStatus(t, resp, 404)

	// Close listener
	ln.Close() //nolint:errcheck

	// Setup new custom listener with unauthenticated metrics access
	ln, addr = TestListener(t)
	props := &vault.HandlerProperties{
		Core: core,
		ListenerConfig: &configutil.Listener{
			Telemetry: configutil.ListenerTelemetry{
				MetricsOnly: true,
				MetricsPath: "/metrics",
			},
		},
	}
	TestServerWithListenerAndProperties(t, ln, addr, core, props)
	defer ln.Close() //nolint:errcheck
	TestServerAuth(t, addr, token)

	// Test with and without token, on default endpoint.
	resp = testHttpGet(t, "", addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 404)
	resp = testHttpGet(t, token, addr+"/v1/sys/metrics")
	testResponseStatus(t, resp, 404)

	// Should work with token, on custom endpoint
	resp = testHttpGet(t, token, addr+"/metrics")
	testResponseStatus(t, resp, 200)

	// Should fail without token, on custom endpoint
	resp = testHttpGet(t, "", addr+"/metrics")
	testResponseStatus(t, resp, 403)

	// Test if prometheus response is correct
	resp = testHttpGet(t, token, addr+"/metrics?format=prometheus")
	testResponseStatus(t, resp, 200)
}
