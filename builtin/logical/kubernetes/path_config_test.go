// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/fileutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

const (
	testLocalCACert = "local ca cert"
	testLocalJWT    = "local jwt"
	testCACert      = "ca cert"
)

func setupLocalFiles(t *testing.T, b logical.Backend) func() {
	cert, err := os.CreateTemp("", "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert.WriteString(testLocalCACert)
	cert.Close()

	token, err := os.CreateTemp("", "token")
	if err != nil {
		t.Fatal(err)
	}
	token.WriteString(testLocalJWT)
	token.Close()
	b.(*backend).localCACertReader = fileutil.NewCachingFileReader(cert.Name(), caReloadPeriod)
	b.(*backend).localSATokenReader = fileutil.NewCachingFileReader(token.Name(), jwtReloadPeriod)

	return func() {
		os.Remove(cert.Name())
		os.Remove(token.Name())
	}
}

func setupK8sEnvVars() func() {
	os.Setenv(k8sServiceHostEnv, "env-host")
	os.Setenv(k8sServicePortEnv, "123")

	return func() {
		defer os.Unsetenv(k8sServiceHostEnv)
		defer os.Unsetenv(k8sServicePortEnv)
	}
}

func Test_configWithDynamicValues(t *testing.T) {
	testCases := map[string]struct {
		config              map[string]interface{}
		setupInClusterFiles bool
		setupK8sEnvVars     bool
		expected            *kubeConfig
	}{
		"empty config uses env": {
			config:              map[string]interface{}{},
			setupInClusterFiles: true,
			setupK8sEnvVars:     true,
			expected: &kubeConfig{
				Host:              "https://env-host:123",
				CACert:            testLocalCACert,
				ServiceAccountJwt: testLocalJWT,
				DisableLocalCAJwt: false,
			},
		},
		"no CA or JWT, default to local": {
			config: map[string]interface{}{
				"kubernetes_host": "host",
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				Host:              "host",
				CACert:            testLocalCACert,
				ServiceAccountJwt: testLocalJWT,
				DisableLocalCAJwt: false,
			},
		},
		"CA set, default to local JWT": {
			config: map[string]interface{}{
				"kubernetes_host":    "host",
				"kubernetes_ca_cert": testCACert,
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				Host:              "host",
				CACert:            testCACert,
				ServiceAccountJwt: testLocalJWT,
				DisableLocalCAJwt: false,
			},
		},
		"JWT set, default to local CA": {
			config: map[string]interface{}{
				"kubernetes_host":     "host",
				"service_account_jwt": "jwt",
			},
			setupInClusterFiles: true,
			expected: &kubeConfig{
				Host:              "host",
				CACert:            testLocalCACert,
				ServiceAccountJwt: "jwt",
				DisableLocalCAJwt: false,
			},
		},
		"CA and disable local default": {
			config: map[string]interface{}{
				"kubernetes_host":      "host",
				"kubernetes_ca_cert":   testCACert,
				"disable_local_ca_jwt": true,
			},
			expected: &kubeConfig{
				Host:              "host",
				CACert:            testCACert,
				ServiceAccountJwt: "",
				DisableLocalCAJwt: true,
			},
		},
		"no CA and disable local default": {
			config: map[string]interface{}{
				"kubernetes_host":      "host",
				"disable_local_ca_jwt": true,
			},
			expected: &kubeConfig{
				Host:              "host",
				CACert:            "",
				ServiceAccountJwt: "",
				DisableLocalCAJwt: true,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			b, storage := getTestBackend(t)

			if tc.setupInClusterFiles {
				cleanup := setupLocalFiles(t, b)
				defer cleanup()
			}
			if tc.setupK8sEnvVars {
				cleanup := setupK8sEnvVars()
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

			conf, err := b.configWithDynamicValues(context.Background(), storage)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.expected, conf, "expected kubeconfig did not match the return from configWithDynamicValues()")

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      configPath,
				Storage:   storage,
				Data:      nil,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			// check that the config elements sent in are returned from read
			for k, v := range tc.config {
				if k == "service_account_jwt" {
					continue
				}
				assert.Equal(t, v, resp.Data[k])
			}
			// check that the other config elements returned are empty
			for k, v := range resp.Data {
				if _, ok := tc.config[k]; !ok {
					assert.Empty(t, v)
				}
			}
			assert.NotContains(t, resp.Data, "service_account_jwt")
		})
	}
}

func Test_getHostFromEnv(t *testing.T) {
	t.Run("not set", func(t *testing.T) {
		host, err := getK8sURLFromEnv()
		assert.EqualError(t, err, `failed to find k8s API host variables "KUBERNETES_SERVICE_HOST" and "KUBERNETES_SERVICE_PORT_HTTPS" in env`)
		assert.Empty(t, host)
	})
	t.Run("both set", func(t *testing.T) {
		os.Setenv(k8sServiceHostEnv, "some-host")
		defer os.Unsetenv(k8sServiceHostEnv)
		os.Setenv(k8sServicePortEnv, "123")
		defer os.Unsetenv(k8sServicePortEnv)
		host, err := getK8sURLFromEnv()
		assert.NoError(t, err)
		assert.Equal(t, "https://some-host:123", host)
	})
	t.Run("one set", func(t *testing.T) {
		os.Setenv(k8sServiceHostEnv, "some-host")
		defer os.Unsetenv(k8sServiceHostEnv)
		host, err := getK8sURLFromEnv()
		assert.EqualError(t, err, `failed to find k8s API host variables "KUBERNETES_SERVICE_HOST" and "KUBERNETES_SERVICE_PORT_HTTPS" in env`)
		assert.Empty(t, host)
	})
}
