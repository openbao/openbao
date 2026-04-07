// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tsaarni/certyaml"

	"golang.org/x/crypto/ocsp"

	logicaltest "github.com/openbao/openbao/helper/testhelpers/logical"

	"github.com/openbao/openbao/sdk/v2/logical"
)

var ocspPort int

var source InMemorySource

type testLogger struct{}

func (t *testLogger) Log(args ...any) {
	fmt.Printf("%v", args)
}

func TestMain(m *testing.M) {
	source = make(InMemorySource)

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return
	}

	ocspPort = listener.Addr().(*net.TCPAddr).Port
	srv := &http.Server{
		Addr:    "localhost:0",
		Handler: NewResponder(&testLogger{}, source, nil),
	}
	go func() {
		srv.Serve(listener) //nolint:errcheck // ignore error
	}()
	defer srv.Shutdown(context.Background()) //nolint:errcheck // ignore error
	_ = m.Run()
}

func TestCert_RoleResolve(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"DNS:example.com", "IP:127.0.0.1"},
		Issuer:          ca,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "example.com"}, false),
			testAccStepLoginWithName(t, connState, "web"),
			testAccStepResolveRoleWithName(t, connState, "web"),
		},
	})
}

func testAccStepResolveRoleWithName(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ResolveRoleOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Data["role"] != certName {
				t.Fatalf("Role was not as expected. Expected %s, received %s", certName, resp.Data["role"])
			}
			return nil
		},
		Data: map[string]interface{}{
			"name": certName,
		},
	}
}

func TestCert_RoleResolveWithoutProvidingCertName(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"DNS:example.com", "IP:127.0.0.1"},
		Issuer:          ca,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "example.com"}, false),
			testAccStepLoginWithName(t, connState, "web"),
			testAccStepResolveRoleWithEmptyDataMap(t, connState, "web"),
		},
	})
}

func testAccStepResolveRoleWithEmptyDataMap(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ResolveRoleOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Data["role"] != certName {
				t.Fatalf("Role was not as expected. Expected %s, received %s", certName, resp.Data["role"])
			}
			return nil
		},
		Data: map[string]interface{}{},
	}
}

func testAccStepResolveRoleExpectRoleResolutionToFail(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ResolveRoleOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		ErrorOk:         true,
		Check: func(resp *logical.Response) error {
			if resp == nil && !resp.IsError() {
				t.Fatalf("Response was not an error: resp:%#v", resp)
			}

			errString, ok := resp.Data["error"].(string)
			if !ok {
				t.Fatal("Error not part of response.")
			}

			if !strings.Contains(errString, "invalid certificate") {
				t.Fatalf("Error was not due to invalid role name. Error: %s", errString)
			}
			return nil
		},
		Data: map[string]interface{}{
			"name": certName,
		},
	}
}

func testAccStepResolveRoleOCSPFail(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ResolveRoleOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		ErrorOk:         true,
		Check: func(resp *logical.Response) error {
			if resp == nil || !resp.IsError() {
				t.Fatalf("Response was not an error: resp:%#v", resp)
			}

			errString, ok := resp.Data["error"].(string)
			if !ok {
				t.Fatal("Error not part of response.")
			}

			if !strings.Contains(errString, "no chain matching") {
				t.Fatalf("Error was not due to OCSP failure. Error: %s", errString)
			}
			return nil
		},
		Data: map[string]interface{}{
			"name": certName,
		},
	}
}

func TestCert_RoleResolve_RoleDoesNotExist(t *testing.T) {
	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"DNS:example.com", "IP:127.0.0.1"},
		Issuer:          ca,
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca.CertPEM(), "foo", allowed{dns: "example.com"}, false),
			testAccStepLoginWithName(t, connState, "web"),
			testAccStepResolveRoleExpectRoleResolutionToFail(t, connState, "notweb"),
		},
	})
}

func TestCert_RoleResolveOCSP(t *testing.T) {
	cases := []struct {
		name        string
		failOpen    bool
		certStatus  int
		errExpected bool
	}{
		{"failFalseGoodCert", false, ocsp.Good, false},
		{"failFalseRevokedCert", false, ocsp.Revoked, true},
		{"failFalseUnknownCert", false, ocsp.Unknown, true},
		{"failTrueGoodCert", true, ocsp.Good, false},
		{"failTrueRevokedCert", true, ocsp.Revoked, true},
		{"failTrueUnknownCert", true, ocsp.Unknown, false},
	}

	ca := &certyaml.Certificate{
		Subject: "cn=ca",
	}

	cert := &certyaml.Certificate{
		Subject:         "cn=example.com",
		SubjectAltNames: []string{"DNS:example.com", "IP:127.0.0.1"},
		Issuer:          ca,
		OCSP:            []string{fmt.Sprintf("http://localhost:%d", ocspPort)},
	}

	connState, err := testConnState(cert, ca)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}

	issuerCert, err := ca.X509Certificate()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	issuerKey, err := ca.PrivateKey()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Get the generated cert to access its serial number.
	x509Cert, err := cert.X509Certificate()
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := ocsp.CreateResponse(&issuerCert, &issuerCert, ocsp.Response{
				Status:       c.certStatus,
				SerialNumber: x509Cert.SerialNumber,
				ProducedAt:   time.Now(),
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().Add(time.Hour),
			}, issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			source[x509Cert.SerialNumber.String()] = resp

			b := testFactory(t)
			b.(*backend).ocspClient.ClearCache()
			var resolveStep logicaltest.TestStep
			var loginStep logicaltest.TestStep
			if c.errExpected {
				loginStep = testAccStepLoginWithNameInvalid(t, connState, "web")
				resolveStep = testAccStepResolveRoleOCSPFail(t, connState, "web")
			} else {
				loginStep = testAccStepLoginWithName(t, connState, "web")
				resolveStep = testAccStepResolveRoleWithName(t, connState, "web")
			}
			logicaltest.Test(t, logicaltest.TestCase{
				CredentialBackend: b,
				Steps: []logicaltest.TestStep{
					testAccStepCertWithExtraParams(t, "web", ca.CertPEM(), "foo", allowed{dns: "example.com"}, false,
						map[string]interface{}{"ocsp_enabled": true, "ocsp_fail_open": c.failOpen}),
					testAccStepReadCertPolicy(t, "web", false, map[string]interface{}{"ocsp_enabled": true, "ocsp_fail_open": c.failOpen}),
					loginStep,
					resolveStep,
				},
			})
		})
	}
}
