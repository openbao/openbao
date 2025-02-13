// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func Test_kubeAuthBackend_updateTLSConfig(t *testing.T) {
	defaultCertPool := getTestCertPool(t, testCACert)
	localCertPool := getTestCertPool(t, testLocalCACert)
	otherCertPool := getTestCertPool(t, testOtherCACert)

	type testConfig struct {
		config          *kubeConfig
		expectTLSConfig *tls.Config
		localCACert     string
		wantErr         bool
		expectError     error
	}
	tests := []struct {
		name       string
		httpClient *http.Client
		tlsConfig  *tls.Config
		wantErr    bool
		configs    []testConfig
	}{
		{
			name:       "fail-client-not-set",
			httpClient: nil,
			configs: []testConfig{
				{
					wantErr:     true,
					expectError: errHTTPClientNotSet,
				},
			},
		},
		{
			name:       "fail-tlsConfig-not-set",
			httpClient: getDefaultHTTPClient(),
			configs: []testConfig{
				{
					wantErr:     true,
					expectError: errTLSConfigNotSet,
				},
			},
		},
		{
			name:       "ca-certs-from-config-source",
			httpClient: getDefaultHTTPClient(),
			tlsConfig:  getDefaultTLSConfig(),
			wantErr:    false,
			configs: []testConfig{
				{
					config: &kubeConfig{
						CACert:            testCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
				},
				{
					config: &kubeConfig{
						CACert:            testLocalCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    localCertPool,
					},
				},
				{
					config: &kubeConfig{
						CACert:            testCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
				},
			},
		},
		{
			name:       "ca-certs-from-file-source",
			httpClient: getDefaultHTTPClient(),
			tlsConfig:  getDefaultTLSConfig(),
			configs: []testConfig{
				{
					config: &kubeConfig{
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
					localCACert: testCACert,
				},
				{
					config: &kubeConfig{
						DisableLocalCAJwt: false,
					},
					localCACert: testLocalCACert,
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    localCertPool,
					},
				},
			},
			wantErr: false,
		},
		{
			name:       "ca-certs-mixed-source",
			httpClient: getDefaultHTTPClient(),
			tlsConfig:  getDefaultTLSConfig(),
			configs: []testConfig{
				{
					config: &kubeConfig{
						CACert:            testCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
				},
				{
					config: &kubeConfig{
						DisableLocalCAJwt: false,
					},
					localCACert: testLocalCACert,
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    localCertPool,
					},
				},
				{
					config: &kubeConfig{
						CACert:            testOtherCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    otherCertPool,
					},
				},
				{
					config: &kubeConfig{
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
					localCACert: testCACert,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &kubeAuthBackend{
				Backend:    &framework.Backend{},
				httpClient: tt.httpClient,
				tlsConfig:  tt.tlsConfig,
			}

			if err := b.Setup(context.Background(),
				&logical.BackendConfig{
					Logger: hclog.NewNullLogger(),
				}); err != nil {
				t.Fatalf("failed to setup the backend, err=%v", err)
			}

			localFile := filepath.Join(t.TempDir(), "ca.crt")
			b.localCACertReader = &cachingFileReader{
				path:        localFile,
				currentTime: time.Now().UTC,
				ttl:         0,
			}
			for idx, config := range tt.configs {
				t.Run(fmt.Sprintf("config-%d", idx), func(t *testing.T) {
					if config.localCACert != "" {
						if err := os.WriteFile(localFile, []byte(config.localCACert), 0o600); err != nil {
							t.Fatalf("failed to write local file %q", localFile)
						}
						t.Cleanup(func() {
							if err := os.Remove(localFile); err != nil {
								t.Fatal(err)
							}
						})
					}

					err := b.updateTLSConfig(config.config)
					if config.wantErr && err == nil {
						t.Fatalf("updateTLSConfig() error = %v, wantErr %v", err, config.wantErr)
					}

					if !reflect.DeepEqual(err, config.expectError) {
						t.Fatalf("updateTLSConfig() error = %v, expectErr %v", err, config.expectError)
					}

					if config.wantErr {
						return
					}

					b.tlsMu.RLock()
					assertTLSConfigEquals(t, b.tlsConfig, config.expectTLSConfig)
					assertValidTransport(t, b, config.expectTLSConfig)
					b.tlsMu.RUnlock()
				})
			}
		})
	}
}

func Test_kubeAuthBackend_initialize(t *testing.T) {
	defaultCertPool := getTestCertPool(t, testCACert)

	tests := []struct {
		name            string
		httpClient      *http.Client
		ctx             context.Context
		req             *logical.InitializationRequest
		config          *kubeConfig
		tlsConfig       *tls.Config
		expectTLSConfig *tls.Config
		wantErr         bool
		expectErr       error
	}{
		{
			name:       "fail-client-not-set",
			ctx:        context.Background(),
			httpClient: nil,
			tlsConfig:  getDefaultTLSConfig(),
			req: &logical.InitializationRequest{
				Storage: &logical.InmemStorage{},
			},
			config: &kubeConfig{
				CACert:            testCACert,
				DisableLocalCAJwt: false,
			},
			wantErr:   true,
			expectErr: errHTTPClientNotSet,
		},
		{
			name:       "no-config",
			ctx:        context.Background(),
			httpClient: getDefaultHTTPClient(),
			tlsConfig:  getDefaultTLSConfig(),
			req: &logical.InitializationRequest{
				Storage: &logical.InmemStorage{},
			},
			wantErr:   false,
			expectErr: nil,
		},
		{
			name:       "initialized-from-config",
			ctx:        context.Background(),
			httpClient: getDefaultHTTPClient(),
			tlsConfig:  getDefaultTLSConfig(),
			req: &logical.InitializationRequest{
				Storage: &logical.InmemStorage{},
			},
			config: &kubeConfig{
				CACert:            testCACert,
				DisableLocalCAJwt: false,
			},
			expectTLSConfig: &tls.Config{
				MinVersion: minTLSVersion,
				RootCAs:    defaultCertPool,
			},
			wantErr:   false,
			expectErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &kubeAuthBackend{
				Backend:    &framework.Backend{},
				httpClient: tt.httpClient,
				tlsConfig:  tt.tlsConfig,
			}

			if err := b.Setup(context.Background(),
				&logical.BackendConfig{
					Logger:      hclog.NewNullLogger(),
					StorageView: tt.req.Storage,
				}); err != nil {
				t.Fatalf("failed to setup the backend, err=%v", err)
			}

			if tt.config != nil {
				entry, err := logical.StorageEntryJSON(configPath, tt.config)
				if err != nil {
					t.Fatal(err)
				}

				if err := tt.req.Storage.Put(tt.ctx, entry); err != nil {
					t.Fatal(err)
				}
			}

			b.tlsMu.RLock()
			if b.tlsConfigUpdaterRunning {
				b.tlsMu.RUnlock()
				t.Fatal("tlsConfigUpdater started before initialize()")
			}
			b.tlsMu.RUnlock()

			ctx, _ := context.WithTimeout(tt.ctx, time.Second*30)
			err := b.initialize(ctx, tt.req)
			if tt.wantErr && err == nil {
				t.Errorf("initialize() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(err, tt.expectErr) {
				t.Fatalf("initialize() error = %v, expectErr %v", err, tt.expectErr)
			}

			if tt.wantErr {
				return
			}

			if tt.config != nil {
				b.tlsMu.RLock()
				assertTLSConfigEquals(t, b.tlsConfig, tt.expectTLSConfig)
				assertValidTransport(t, b, tt.expectTLSConfig)
				b.tlsMu.RUnlock()
			}

			b.tlsMu.RLock()
			if !b.tlsConfigUpdaterRunning {
				b.tlsMu.RUnlock()
				t.Fatal("tlsConfigUpdater not started from initialize()")
			}
			b.tlsMu.RUnlock()
		})
	}
}

func Test_kubeAuthBackend_runTLSConfigUpdater(t *testing.T) {
	defaultCertPool := getTestCertPool(t, testCACert)
	otherCertPool := getTestCertPool(t, testOtherCACert)

	type testConfig struct {
		config          *kubeConfig
		expectTLSConfig *tls.Config
	}

	tests := []struct {
		name       string
		ctx        context.Context
		storage    logical.Storage
		tlsConfig  *tls.Config
		horizon    time.Duration
		minHorizon time.Duration
		wantErr    bool
		expectErr  error
		configs    []*testConfig
	}{
		{
			name:       "initialized-from-config",
			tlsConfig:  getDefaultTLSConfig(),
			ctx:        context.Background(),
			storage:    &logical.InmemStorage{},
			horizon:    time.Millisecond * 500,
			minHorizon: time.Millisecond * 499,
			wantErr:    false,
			expectErr:  nil,
			configs: []*testConfig{
				{
					config: &kubeConfig{
						CACert:            testCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    defaultCertPool,
					},
				},
				{
					config: &kubeConfig{
						CACert:            testOtherCACert,
						DisableLocalCAJwt: false,
					},
					expectTLSConfig: &tls.Config{
						MinVersion: minTLSVersion,
						RootCAs:    otherCertPool,
					},
				},
			},
		},
		{
			name:      "fail-min-horizon",
			ctx:       context.Background(),
			storage:   &logical.InmemStorage{},
			horizon:   time.Millisecond * 500,
			wantErr:   true,
			expectErr: fmt.Errorf("update horizon must be equal to or greater than %s", defaultMinHorizon),
		},
	}

	d := defaultMinHorizon
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.minHorizon > 0 {
				defer (func() {
					defaultMinHorizon = d
				})()
				defaultMinHorizon = tt.minHorizon
			}
			b := &kubeAuthBackend{
				Backend:    &framework.Backend{},
				httpClient: getDefaultHTTPClient(),
				tlsConfig:  tt.tlsConfig,
			}

			if err := b.Setup(context.Background(),
				&logical.BackendConfig{
					Logger:      hclog.NewNullLogger(),
					StorageView: tt.storage,
				}); err != nil {
				t.Fatalf("failed to setup the backend, err=%v", err)
			}

			b.tlsMu.RLock()
			if b.tlsConfigUpdaterRunning {
				b.tlsMu.RUnlock()
				t.Fatal("tlsConfigUpdater already started")
			}
			b.tlsMu.RUnlock()

			configCount := len(tt.configs)
			ctx, cancel := context.WithTimeout(tt.ctx, tt.horizon*time.Duration(configCount*2))
			defer cancel()
			err := b.runTLSConfigUpdater(ctx, tt.storage, tt.horizon)
			if tt.wantErr && err == nil {
				t.Errorf("runTLSConfigUpdater() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(err, tt.expectErr) {
				t.Fatalf("runTLSConfigUpdater() error = %v, expectErr %v", err, tt.expectErr)
			}

			if tt.wantErr {
				return
			}

			b.tlsMu.RLock()
			if !b.tlsConfigUpdaterRunning {
				b.tlsMu.RUnlock()
				t.Fatal("tlsConfigUpdater not started")
			}
			b.tlsMu.RUnlock()

			if configCount > 0 {
				for idx := 0; idx < configCount; idx++ {
					t.Run(fmt.Sprintf("config-%d", idx), func(t *testing.T) {
						config := tt.configs[idx]
						if config.config != nil {
							entry, err := logical.StorageEntryJSON(configPath, config.config)
							if err != nil {
								t.Fatal(err)
							}

							if err := tt.storage.Put(tt.ctx, entry); err != nil {
								t.Fatal(err)
							}
						}

						time.Sleep(tt.horizon * 2)
						if b.tlsConfig == nil {
							t.Fatal("runTLSConfigUpdater(), expected tlsConfig initialization")
						}

						b.tlsMu.RLock()
						assertTLSConfigEquals(t, b.tlsConfig, config.expectTLSConfig)
						assertValidTransport(t, b, config.expectTLSConfig)
						b.tlsMu.RUnlock()
					})
				}
			} else {
				if b.tlsConfig != nil {
					t.Error("runTLSConfigUpdater(), unexpected tlsConfig initialization")
				}
			}

			cancel()
			time.Sleep(tt.horizon)
			b.tlsMu.RLock()
			if b.tlsConfigUpdaterRunning {
				b.tlsMu.RUnlock()
				t.Fatal("tlsConfigUpdater did not shutdown cleanly")
			}
			b.tlsMu.RUnlock()
		})
	}
}

func assertTLSConfigEquals(t *testing.T, actual, expected *tls.Config) {
	t.Helper()

	if !actual.RootCAs.Equal(expected.RootCAs) {
		t.Errorf("updateTLSConfig() actual RootCAs = %v, expected RootCAs %v",
			actual.RootCAs, expected.RootCAs)
	}
	if actual.MinVersion != expected.MinVersion {
		t.Errorf("updateTLSConfig() actual MinVersion = %v, expected MinVersion %v",
			actual.MinVersion, expected.MinVersion)
	}
}

func assertValidTransport(t *testing.T, b *kubeAuthBackend, expected *tls.Config) {
	t.Helper()

	transport, ok := b.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("type assertion failed for %T", b.httpClient.Transport)
	}

	assertTLSConfigEquals(t, transport.TLSClientConfig, expected)
}

func getTestCertPool(t *testing.T, cert string) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(cert)); !ok {
		t.Fatal("test certificate contains no valid certificates")
	}
	return pool
}
