// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"crypto"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupLocalFiles(t *testing.T, b logical.Backend) func() {
	cert, err := os.CreateTemp("", "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cert.WriteString(testLocalCACert)
	if err != nil {
		t.Fatal(err)
	}
	cert.Close()

	token, err := os.CreateTemp("", "token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = token.WriteString(testLocalJWT)
	if err != nil {
		t.Fatal(err)
	}
	token.Close()
	b.(*kubeAuthBackend).localCACertReader = newCachingFileReader(cert.Name(), caReloadPeriod, time.Now)
	b.(*kubeAuthBackend).localSATokenReader = newCachingFileReader(token.Name(), jwtReloadPeriod, time.Now)

	return func() {
		os.Remove(cert.Name())
		os.Remove(token.Name())
	}
}

func TestConfig_Read(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "token-review-jwt-is-unset",
			data: map[string]interface{}{
				"pem_keys":               []string{testRSACert, testECCert},
				"kubernetes_host":        "host",
				"kubernetes_ca_cert":     testCACert,
				"issuer":                 "",
				"disable_iss_validation": false,
				"disable_local_ca_jwt":   false,
			},
			want: map[string]interface{}{
				"pem_keys":               []string{testRSACert, testECCert},
				"kubernetes_host":        "host",
				"kubernetes_ca_cert":     testCACert,
				"issuer":                 "",
				"disable_iss_validation": false,
				"disable_local_ca_jwt":   false,
				"token_reviewer_jwt_set": false,
			},
		},
		{
			name: "token-review-jwt-is-set",
			data: map[string]interface{}{
				"pem_keys":               []string{testRSACert, testECCert},
				"kubernetes_host":        "host",
				"kubernetes_ca_cert":     testCACert,
				"issuer":                 "",
				"disable_iss_validation": false,
				"disable_local_ca_jwt":   false,
				"token_reviewer_jwt":     "test-token-review-jwt",
			},
			want: map[string]interface{}{
				"pem_keys":               []string{testRSACert, testECCert},
				"kubernetes_host":        "host",
				"kubernetes_ca_cert":     testCACert,
				"issuer":                 "",
				"disable_iss_validation": false,
				"disable_local_ca_jwt":   false,
				"token_reviewer_jwt_set": true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getBackend(t)
			cleanup := setupLocalFiles(t, b)
			t.Cleanup(cleanup)

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("got unexpected error %s for resp %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      nil,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("got unexpected error %s for resp %#v", err, resp)
			}

			if !reflect.DeepEqual(resp.Data, tc.want) {
				t.Fatalf("expected %#v, got %#v", tc.want, resp.Data)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	b, storage := getBackend(t)

	cleanup := setupLocalFiles(t, b)
	defer cleanup()

	// test no certificate
	data := map[string]interface{}{
		"kubernetes_host": "host",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test no host
	data = map[string]interface{}{
		"pem_keys": testRSACert,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "no host provided" {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// test invalid cert
	data = map[string]interface{}{
		"pem_keys":        "bad",
		"kubernetes_host": "host",
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "data does not contain any valid public keys" {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// Test success with no certs
	data = map[string]interface{}{
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	expected := &kubeConfig{
		PublicKeys:           []crypto.PublicKey{},
		PEMKeys:              []string{},
		Host:                 "host",
		CACert:               testCACert,
		DisableISSValidation: true,
	}

	conf, err := b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success TokenReviewer
	data = map[string]interface{}{
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
		"token_reviewer_jwt": jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err := certutil.ParsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("expected cert to be non-nil")
	}

	expected = &kubeConfig{
		PublicKeys:           []crypto.PublicKey{},
		PEMKeys:              []string{},
		Host:                 "host",
		CACert:               testCACert,
		TokenReviewerJWT:     jwtGoodDataToken,
		DisableISSValidation: true,
		DisableLocalCAJwt:    false,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success with one cert
	data = map[string]interface{}{
		"pem_keys":           testRSACert,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = certutil.ParsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	expected = &kubeConfig{
		PublicKeys:           []crypto.PublicKey{cert},
		PEMKeys:              []string{testRSACert},
		Host:                 "host",
		CACert:               testCACert,
		DisableISSValidation: true,
		DisableLocalCAJwt:    false,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success with two certs
	data = map[string]interface{}{
		"pem_keys":           []string{testRSACert, testECCert},
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = certutil.ParsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := certutil.ParsePublicKeyPEM([]byte(testECCert))
	if err != nil {
		t.Fatal(err)
	}

	expected = &kubeConfig{
		PublicKeys:           []crypto.PublicKey{cert, cert2},
		PEMKeys:              []string{testRSACert, testECCert},
		Host:                 "host",
		CACert:               testCACert,
		DisableISSValidation: true,
		DisableLocalCAJwt:    false,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success with disabled iss validation
	data = map[string]interface{}{
		"kubernetes_host":        "host",
		"kubernetes_ca_cert":     testCACert,
		"disable_iss_validation": true,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = certutil.ParsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("expected cert to be non-nil")
	}

	expected = &kubeConfig{
		PublicKeys:           []crypto.PublicKey{},
		PEMKeys:              []string{},
		Host:                 "host",
		CACert:               testCACert,
		DisableISSValidation: true,
		DisableLocalCAJwt:    false,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}
}

func TestConfig_LocalCaJWT(t *testing.T) {
	testCases := map[string]struct {
		config              map[string]interface{}
		setupInClusterFiles bool
		expected            *kubeConfig
	}{
		"no CA or JWT, default to local": {
			config: map[string]interface{}{
				"kubernetes_host": "host",
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				PublicKeys:           []crypto.PublicKey{},
				PEMKeys:              []string{},
				Host:                 "host",
				CACert:               testLocalCACert,
				TokenReviewerJWT:     testLocalJWT,
				DisableISSValidation: true,
				DisableLocalCAJwt:    false,
			},
		},
		"CA set, default to local JWT": {
			config: map[string]interface{}{
				"kubernetes_host":    "host",
				"kubernetes_ca_cert": testCACert,
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				PublicKeys:           []crypto.PublicKey{},
				PEMKeys:              []string{},
				Host:                 "host",
				CACert:               testCACert,
				TokenReviewerJWT:     testLocalJWT,
				DisableISSValidation: true,
				DisableLocalCAJwt:    false,
			},
		},
		"JWT set, default to local CA": {
			config: map[string]interface{}{
				"kubernetes_host":    "host",
				"token_reviewer_jwt": jwtGoodDataToken,
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				PublicKeys:           []crypto.PublicKey{},
				PEMKeys:              []string{},
				Host:                 "host",
				CACert:               testLocalCACert,
				TokenReviewerJWT:     jwtGoodDataToken,
				DisableISSValidation: true,
				DisableLocalCAJwt:    false,
			},
		},
		"CA and disable local default": {
			config: map[string]interface{}{
				"kubernetes_host":      "host",
				"kubernetes_ca_cert":   testCACert,
				"disable_local_ca_jwt": true,
			},
			expected: &kubeConfig{
				PublicKeys:           []crypto.PublicKey{},
				PEMKeys:              []string{},
				Host:                 "host",
				CACert:               testCACert,
				TokenReviewerJWT:     "",
				DisableISSValidation: true,
				DisableLocalCAJwt:    true,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)

			if tc.setupInClusterFiles {
				cleanup := setupLocalFiles(t, b)
				defer cleanup()
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      tc.config,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			conf, err := b.(*kubeAuthBackend).loadConfig(context.Background(), storage)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, conf) {
				t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", tc.expected, conf)
			}
		})
	}
}

func TestConfig_LocalJWTRenewal(t *testing.T) {
	b, storage := getBackend(t)

	cleanup := setupLocalFiles(t, b)
	defer cleanup()

	// Create temp file that will be used as token.
	f, err := os.CreateTemp("", "renewed-token")
	if err != nil {
		t.Error(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	currentTime := time.Now()

	b.(*kubeAuthBackend).localSATokenReader = newCachingFileReader(f.Name(), jwtReloadPeriod, func() time.Time {
		return currentTime
	})

	token1 := "before-renewal"
	token2 := "after-renewal"

	// Write initial token to the temp file.
	err = os.WriteFile(f.Name(), []byte(token1), 0o644)
	if err != nil {
		t.Error(err)
	}

	data := map[string]interface{}{
		"kubernetes_host": "host",
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Loading the config will load the initial token file from disk.
	conf, err := b.(*kubeAuthBackend).loadConfig(context.Background(), storage)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Check that we loaded the initial token.
	if conf.TokenReviewerJWT != token1 {
		t.Fatalf("got unexpected JWT: expected %#v\n got %#v\n", token1, conf.TokenReviewerJWT)
	}

	// Write new value to the token file to simulate renewal.
	err = os.WriteFile(f.Name(), []byte(token2), 0o644)
	if err != nil {
		t.Error(err)
	}

	// Load again to check we still got the old cached token from memory.
	conf, err = b.(*kubeAuthBackend).loadConfig(context.Background(), storage)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if conf.TokenReviewerJWT != token1 {
		t.Fatalf("got unexpected JWT: expected %#v\n got %#v\n", token1, conf.TokenReviewerJWT)
	}

	// Advance simulated time for cache to expire
	currentTime = currentTime.Add(1 * time.Minute)

	// Load again and check we the new renewed token from disk.
	conf, err = b.(*kubeAuthBackend).loadConfig(context.Background(), storage)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if conf.TokenReviewerJWT != token2 {
		t.Fatalf("got unexpected JWT: expected %#v\n got %#v\n", token2, conf.TokenReviewerJWT)
	}
}
