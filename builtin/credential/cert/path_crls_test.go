// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
)

func TestCRLFetch(t *testing.T) {
	tc := setupTestCerts(t)
	storage := &logical.InmemStorage{}

	lb, err := Factory(t.Context(), &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 300 * time.Second,
			MaxLeaseTTLVal:     1800 * time.Second,
		},
		StorageView: storage,
	})

	require.NoError(t, err)
	b := lb.(*backend)
	closeChan := make(chan bool)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				require.NoError(t, b.PeriodicFunc(t.Context(), &logical.Request{Storage: storage}))
			case <-closeChan:
			}
		}
	}()
	defer close(closeChan)

	connState, err := testConnState(tc.exampleCert, tc.exampleCA)
	require.NoError(t, err)

	revokedCert1 := &certyaml.Certificate{Subject: "cn=revoked1", Issuer: tc.exampleCA}
	revokedCert2 := &certyaml.Certificate{Subject: "cn=revoked2", Issuer: tc.exampleCA}

	nextUpdate := time.Now().Add(50 * time.Millisecond)
	crl1 := &certyaml.CRL{
		Issuer:     tc.exampleCA,
		Revoked:    []*certyaml.Certificate{revokedCert1},
		NextUpdate: &nextUpdate,
	}
	crlDER, err := crl1.DER()
	require.NoError(t, err)

	var crlBytesLock sync.Mutex
	crlBytes := crlDER

	var serverURL *url.URL
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == serverURL.Host {
			crlBytesLock.Lock()
			w.Write(crlBytes)
			crlBytesLock.Unlock()
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL, _ = url.Parse(crlServer.URL)

	req := &logical.Request{
		Connection: &logical.Connection{
			ConnState: &connState,
		},
		Storage: storage,
		Auth:    &logical.Auth{},
	}

	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        "test",
			"certificate": tc.exampleCA.CertPEM(),
			"policies":    "foo,bar",
		},
		Schema: pathCerts(b).Fields,
	}

	_, err = b.pathCertWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	empty_login_fd := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: pathLogin(b).Fields,
	}
	resp, err := b.pathLogin(t.Context(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Set a bad CRL
	fd = &framework.FieldData{
		Raw: map[string]interface{}{
			"name": "testcrl",
			"url":  "http://wrongserver.com",
		},
		Schema: pathCRLs(b).Fields,
	}
	resp, err = b.pathCRLWrite(t.Context(), req, fd)
	if err == nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Set good CRL
	fd = &framework.FieldData{
		Raw: map[string]interface{}{
			"name": "testcrl",
			"url":  crlServer.URL,
		},
		Schema: pathCRLs(b).Fields,
	}
	resp, err = b.pathCRLWrite(t.Context(), req, fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	b.crlUpdateMutex.Lock()
	if len(b.crls["testcrl"].Serials) != 1 {
		t.Fatalf("wrong number of certs in CRL got %d, expected 1", len(b.crls["testcrl"].Serials))
	}
	b.crlUpdateMutex.Unlock()

	nextUpdate2 := time.Now().Add(1 * time.Minute)
	crl2 := &certyaml.CRL{
		Issuer:     tc.exampleCA,
		Revoked:    []*certyaml.Certificate{revokedCert1, revokedCert2},
		NextUpdate: &nextUpdate2,
	}
	crlDER2, err := crl2.DER()
	require.NoError(t, err)

	crlBytesLock.Lock()
	crlBytes = crlDER2
	crlBytesLock.Unlock()

	// Give ourselves a little extra room on slower CI systems to ensure we
	// can fetch the new CRL.
	corehelpers.RetryUntil(t, 2*time.Second, func() error {
		b.crlUpdateMutex.Lock()
		defer b.crlUpdateMutex.Unlock()

		serialCount := len(b.crls["testcrl"].Serials)
		if serialCount != 2 {
			return fmt.Errorf("CRL refresh did not occur serial count %d", serialCount)
		}
		return nil
	})
}
