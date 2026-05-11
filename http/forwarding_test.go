// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/openbao/openbao/api/v2"
	credCert "github.com/openbao/openbao/builtin/credential/cert"
	"github.com/openbao/openbao/builtin/logical/transit"
	"github.com/openbao/openbao/helper/configutil"
	"github.com/openbao/openbao/helper/testhelpers"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/helper/pointerutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestHTTP_Fallback_Bad_Address(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
		ClusterAddr: "https://127.3.4.1:8382",
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	addrs := []string{
		fmt.Sprintf("https://127.0.0.1:%d", cores[1].Listeners[0].Address.Port),
		fmt.Sprintf("https://127.0.0.1:%d", cores[2].Listeners[0].Address.Port),
	}

	for _, addr := range addrs {
		config := api.DefaultConfig()
		config.Address = addr
		config.HttpClient.Transport.(*http.Transport).TLSClientConfig = cores[0].TLSConfig()

		client, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		client.SetToken(cluster.RootToken)

		secret, err := client.Auth().Token().LookupSelf()
		if err != nil {
			t.Fatal(err)
		}
		if secret == nil {
			t.Fatal("secret is nil")
		}
		if secret.Data["id"].(string) != cluster.RootToken {
			t.Fatal("token mismatch")
		}
	}
}

func TestHTTP_Fallback_Disabled(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
		ClusterAddr: "empty",
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	addrs := []string{
		fmt.Sprintf("https://127.0.0.1:%d", cores[1].Listeners[0].Address.Port),
		fmt.Sprintf("https://127.0.0.1:%d", cores[2].Listeners[0].Address.Port),
	}

	for _, addr := range addrs {
		config := api.DefaultConfig()
		config.Address = addr
		config.HttpClient.Transport.(*http.Transport).TLSClientConfig = cores[0].TLSConfig()

		client, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		client.SetToken(cluster.RootToken)

		secret, err := client.Auth().Token().LookupSelf()
		if err != nil {
			t.Fatal(err)
		}
		if secret == nil {
			t.Fatal("secret is nil")
		}
		if secret.Data["id"].(string) != cluster.RootToken {
			t.Fatal("token mismatch")
		}
	}
}

// This function recreates the fuzzy testing from transit to pipe a large
// number of requests from the standbys to the active node.
func TestHTTP_Forwarding_Stress(t *testing.T) {
	testHTTP_Forwarding_Stress_Common(t, false, 50)
	testHTTP_Forwarding_Stress_Common(t, true, 50)
}

func testHTTP_Forwarding_Stress_Common(t *testing.T, parallel bool, num uint32) {
	testPlaintext := "the quick brown fox"
	testPlaintextB64 := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc:         Handler,
		DisableStandbyReads: true,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	wg := sync.WaitGroup{}

	funcs := []string{"encrypt", "decrypt", "rotate", "change_min_version"}
	keys := []string{"test1", "test2", "test3"}

	hosts := []string{
		fmt.Sprintf("https://127.0.0.1:%d/v1/transit/", cores[1].Listeners[0].Address.Port),
		fmt.Sprintf("https://127.0.0.1:%d/v1/transit/", cores[2].Listeners[0].Address.Port),
	}

	transport := &http.Transport{
		TLSClientConfig: cores[0].TLSConfig(),
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects not allowed in this test")
		},
	}

	// core.Logger().Printf("[TRACE] mounting transit")
	req, err := http.NewRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/v1/sys/mounts/transit", cores[0].Listeners[0].Address.Port),
		bytes.NewBuffer([]byte("{\"type\": \"transit\"}")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(consts.AuthHeaderName, cluster.RootToken)
	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	totalOps := atomic.Uint32{}
	successfulOps := atomic.Uint32{}
	key1ver := atomic.Int32{}
	key1ver.Store(1)

	key2ver := atomic.Int32{}
	key2ver.Store(1)

	key3ver := atomic.Int32{}
	key3ver.Store(1)

	numWorkers := atomic.Uint32{}
	numWorkers.Store(50)
	numWorkersStarted := atomic.Uint32{}
	var waitLock sync.Mutex
	waitCond := sync.NewCond(&waitLock)

	// This is the goroutine loop
	doFuzzy := func(id int, parallel bool) {
		var myTotalOps uint32
		var mySuccessfulOps uint32
		var keyVer int32 = 1
		// Check for panics, otherwise notify we're done
		defer func() {
			if err := recover(); err != nil {
				core.Logger().Error("got a panic", "error", err)
				t.Fail()
			}
			totalOps.Add(myTotalOps)
			successfulOps.Add(mySuccessfulOps)
			wg.Done()
		}()

		// Holds the latest encrypted value for each key
		latestEncryptedText := map[string]string{}

		client := &http.Client{
			Transport: transport,
		}

		var chosenFunc, chosenKey, chosenHost string

		myRand := rand.New(rand.NewSource(int64(id) * 400))

		doReq := func(method, url string, body io.Reader) (*http.Response, error) {
			req, err := http.NewRequest(method, url, body)
			if err != nil {
				return nil, err
			}
			req.Header.Set(consts.AuthHeaderName, cluster.RootToken)
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		doResp := func(resp *http.Response) (*api.Secret, error) {
			if resp == nil {
				return nil, errors.New("nil response")
			}
			defer resp.Body.Close() //nolint:errcheck

			// Make sure we weren't redirected
			if resp.StatusCode > 300 && resp.StatusCode < 400 {
				return nil, fmt.Errorf("got status code %d, resp was %#v", resp.StatusCode, *resp)
			}

			result := &api.Response{Response: resp}
			err := result.Error()
			if err != nil {
				return nil, err
			}

			secret, err := api.ParseSecret(result.Body)
			if err != nil {
				return nil, err
			}

			return secret, nil
		}

		for _, chosenHost := range hosts {
			for _, chosenKey := range keys {
				// Try to write the key to make sure it exists
				_, err := doReq("POST", chosenHost+"keys/"+fmt.Sprintf("%s-%t", chosenKey, parallel), bytes.NewBuffer([]byte("{}")))
				if err != nil {
					panic(err)
				}
			}
		}

		if !parallel {
			chosenHost = hosts[id%len(hosts)]
			chosenKey = fmt.Sprintf("key-%t-%d", parallel, id)

			_, err := doReq("POST", chosenHost+"keys/"+chosenKey, bytes.NewBuffer([]byte("{}")))
			if err != nil {
				panic(err)
			}
		}

		numWorkersStarted.Add(1)

		waitCond.L.Lock()
		for numWorkersStarted.Load() != numWorkers.Load() {
			waitCond.Wait()
		}
		waitCond.L.Unlock()
		waitCond.Broadcast()

		core.Logger().Debug("Starting goroutine", "id", id)

		startTime := time.Now()
		for {
			// Stop after 10 seconds
			if time.Since(startTime) > 10*time.Second {
				return
			}

			myTotalOps++

			// Pick a function and a key
			chosenFunc = funcs[myRand.Int()%len(funcs)]
			if parallel {
				chosenKey = fmt.Sprintf("%s-%t", keys[myRand.Int()%len(keys)], parallel)
				chosenHost = hosts[myRand.Int()%len(hosts)]
			}

			switch chosenFunc {
			// Encrypt our plaintext and store the result
			case "encrypt":
				// core.Logger().Printf("[TRACE] %s, %s, %d", chosenFunc, chosenKey, id)
				resp, err := doReq("POST", chosenHost+"encrypt/"+chosenKey, bytes.NewBuffer(fmt.Appendf(nil, "{\"plaintext\": \"%s\"}", testPlaintextB64)))
				if err != nil {
					panic(err)
				}

				secret, err := doResp(resp)
				if err != nil {
					panic(err)
				}

				latest := secret.Data["ciphertext"].(string)
				if latest == "" {
					panic(errors.New("bad ciphertext"))
				}
				latestEncryptedText[chosenKey] = secret.Data["ciphertext"].(string)

				mySuccessfulOps++

			// Decrypt the ciphertext and compare the result
			case "decrypt":
				ct := latestEncryptedText[chosenKey]
				if ct == "" {
					mySuccessfulOps++
					continue
				}

				// core.Logger().Printf("[TRACE] %s, %s, %d", chosenFunc, chosenKey, id)
				resp, err := doReq("POST", chosenHost+"decrypt/"+chosenKey, bytes.NewBuffer(fmt.Appendf(nil, "{\"ciphertext\": \"%s\"}", ct)))
				if err != nil {
					panic(err)
				}

				secret, err := doResp(resp)
				if err != nil {
					// This could well happen since the min version is jumping around
					if strings.Contains(err.Error(), keysutil.ErrTooOld) {
						mySuccessfulOps++
						continue
					}
					panic(err)
				}

				ptb64 := secret.Data["plaintext"].(string)
				pt, err := base64.StdEncoding.DecodeString(ptb64)
				if err != nil {
					panic(fmt.Errorf("got an error decoding base64 plaintext: %v", err))
				}
				if string(pt) != testPlaintext {
					panic(fmt.Errorf("got bad plaintext back: %s", pt))
				}

				mySuccessfulOps++

			// Rotate to a new key version
			case "rotate":
				// core.Logger().Printf("[TRACE] %s, %s, %d", chosenFunc, chosenKey, id)
				_, err := doReq("POST", chosenHost+"keys/"+chosenKey+"/rotate", bytes.NewBuffer([]byte("{}")))
				if err != nil {
					panic(err)
				}
				if parallel {
					switch chosenKey {
					case "test1":
						key1ver.Add(1)
					case "test2":
						key2ver.Add(1)
					case "test3":
						key3ver.Add(1)
					}
				} else {
					keyVer++
				}

				mySuccessfulOps++

			// Change the min version, which also tests the archive functionality
			case "change_min_version":
				latestVersion := keyVer
				if parallel {
					switch chosenKey {
					case "test1":
						latestVersion = key1ver.Load()
					case "test2":
						latestVersion = key2ver.Load()
					case "test3":
						latestVersion = key3ver.Load()
					}
				}

				setVersion := (myRand.Int31() % latestVersion) + 1

				// core.Logger().Printf("[TRACE] %s, %s, %d, new min version %d", chosenFunc, chosenKey, id, setVersion)

				_, err := doReq("POST", chosenHost+"keys/"+chosenKey+"/config", bytes.NewBuffer(fmt.Appendf(nil, "{\"min_decryption_version\": %d}", setVersion)))
				if err != nil {
					panic(err)
				}

				mySuccessfulOps++
			}
		}
	}

	numWorkers.Store(num)
	// Spawn some of these workers for 10 seconds
	for i := 0; i < int(numWorkers.Load()); i++ {
		wg.Add(1)
		go doFuzzy(i+1, parallel)
	}

	// Wait for them all to finish
	wg.Wait()

	tOps := totalOps.Load()
	sOps := successfulOps.Load()
	if tOps == 0 || tOps != sOps {
		t.Fatalf("total/successful ops zero or mismatch: %d/%d; parallel: %t, num %d", tOps, sOps, parallel, num)
	}
	t.Logf("total operations tried: %d, total successful: %d; parallel: %t, num %d", tOps, sOps, parallel, num)
}

// This tests TLS connection state forwarding by ensuring that we can use a
// client TLS to authenticate against the cert backend
func TestHTTP_Forwarding_ClientTLS(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"cert": credCert.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = cores[0].TLSConfig()
	if err := http2.ConfigureTransport(transport); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/v1/sys/auth/cert", cores[0].Listeners[0].Address.Port),
		bytes.NewBuffer([]byte("{\"type\": \"cert\"}")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(consts.AuthHeaderName, cluster.RootToken)
	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	type certConfig struct {
		Certificate string `json:"certificate"`
		Policies    string `json:"policies"`
	}
	encodedCertConfig, err := json.Marshal(&certConfig{
		Certificate: string(cluster.CACertPEM),
		Policies:    "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/v1/auth/cert/certs/test", cores[0].Listeners[0].Address.Port),
		bytes.NewBuffer(encodedCertConfig))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(consts.AuthHeaderName, cluster.RootToken)
	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	addrs := []string{
		fmt.Sprintf("https://127.0.0.1:%d", cores[1].Listeners[0].Address.Port),
		fmt.Sprintf("https://127.0.0.1:%d", cores[2].Listeners[0].Address.Port),
	}

	for i, addr := range addrs {
		// Ensure we can't possibly use lingering connections even though it should
		// be to a different address
		transport = cleanhttp.DefaultTransport()
		// i starts at zero but cores in addrs start at 1
		transport.TLSClientConfig = cores[i+1].TLSConfig()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		httpClient := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects not allowed in this test")
			},
		}
		client, err := api.NewClient(&api.Config{
			Address:    addr,
			HttpClient: httpClient,
		})
		if err != nil {
			t.Fatal(err)
		}

		secret, err := client.Logical().Write("auth/cert/login", nil)
		if err != nil {
			t.Fatal(err)
		}
		if secret == nil {
			t.Fatal("secret is nil")
		}
		if secret.Auth == nil {
			t.Fatal("auth is nil")
		}
		if len(secret.Auth.Policies) == 0 || secret.Auth.Policies[0] != "default" {
			t.Fatalf("bad policies: %#v", secret.Auth.Policies)
		}
		if secret.Auth.ClientToken == "" {
			t.Fatalf("bad client token: %#v", *secret.Auth)
		}
		client.SetToken(secret.Auth.ClientToken)
		secret, err = client.Auth().Token().LookupSelf()
		if err != nil {
			t.Fatal(err)
		}
		if secret == nil {
			t.Fatal("secret is nil")
		}
		if len(secret.Data) == 0 {
			t.Fatal("secret data was empty")
		}
	}
}

func TestHTTP_Forwarding_HelpOperation(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	testHelp := func(node string, client *api.Client) {
		help, err := client.Help("auth/token")
		if err != nil {
			t.Fatalf("[on %v]: %v", node, err)
		}
		if help == nil {
			t.Fatalf("[on %v]: help was nil", node)
		}
	}

	testHelp("active", cores[0].Client)
	testHelp("standby", cores[1].Client)
}

func TestHTTP_Forwarding_LocalOnly(t *testing.T) {
	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)
	testhelpers.WaitForStandbyNode(t, cluster.Cores[1])
	testhelpers.WaitForStandbyNode(t, cluster.Cores[2])

	testLocalOnly := func(client *api.Client) {
		sec, err := client.Logical().Read("sys/config/state/sanitized")
		if err != nil {
			t.Fatalf("standby should handle local read without forwarding: %v", err)
		}
		if sec == nil || sec.Data == nil {
			t.Fatalf("expected non-nil secret/data from local read")
		}
	}

	testLocalOnly(cores[1].Client)
	testLocalOnly(cores[2].Client)
}

func TestHTTP_Forwarding_StandbySystemEndpoints(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
		DefaultHandlerProperties: vault.HandlerProperties{
			ListenerConfig: &configutil.Listener{
				DisableUnauthedGenerateRootEndpoints: pointerutil.BoolPtr(false),
				DisableUnauthedRekeyEndpoints:        pointerutil.BoolPtr(false),
			},
		},
		NumCores: 2,
	})
	cluster.Start()
	defer cluster.Cleanup()

	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	// Get a client that sends request to a standby.
	standbyClient := func() *api.Client {
		standbys := testhelpers.DeriveStandbyCores(t, cluster)
		require.NotEmpty(t, standbys, "expected at least one standby core")
		return standbys[0].Client
	}

	// Test that generate-root forwards to active.
	otp, err := base62.Random(vault.TokenPrefixLength + vault.TokenLength)
	require.NoError(t, err)
	generateRootResponse, err := standbyClient().Sys().GenerateRootInit(otp, "")
	require.NoError(t, err, "expected no error when request is successfully forwarded to active")
	require.NotNil(t, generateRootResponse)
	for _, k := range cluster.BarrierKeys {
		generateRootResponse, err = standbyClient().Sys().GenerateRootUpdate(base64.StdEncoding.EncodeToString(k), generateRootResponse.Nonce)
		require.NoError(t, err, "expected no error when request is successfully forwarded to active")
	}
	require.True(t, generateRootResponse.Complete)

	// Test that rekey/init forwards to active.
	//nolint:staticcheck // endpoint already marked as deprecated
	rekeyInitResponse, err := standbyClient().Sys().RekeyInit(&api.RekeyInitRequest{
		SecretShares:        1,
		SecretThreshold:     1,
		RequireVerification: true,
	})
	require.NoError(t, err)
	require.NotNil(t, rekeyInitResponse)
	require.True(t, rekeyInitResponse.Started)

	// Test that rekey/update forwards to active.
	var rekeyUpdateResponse *api.RekeyUpdateResponse
	for _, k := range cluster.BarrierKeys {
		//nolint:staticcheck // endpoint already marked as deprecated
		rekeyUpdateResponse, err = standbyClient().Sys().RekeyUpdate(base64.StdEncoding.EncodeToString(k), rekeyInitResponse.Nonce)
		require.NoError(t, err)
	}
	require.True(t, rekeyUpdateResponse.Complete)

	// Test that rekey/verify forwards to active.
	var rekeyVerifyResponse *api.RekeyVerificationUpdateResponse
	for _, k := range rekeyUpdateResponse.Keys {
		//nolint:staticcheck // endpoint already marked as deprecated
		rekeyVerifyResponse, err = standbyClient().Sys().RekeyVerificationUpdate(k, rekeyUpdateResponse.VerificationNonce)
		require.NoError(t, err)
	}
	require.True(t, rekeyVerifyResponse.Complete)

	// Test that step-down forwards to active.
	activeBeforeStepDown := testhelpers.DeriveActiveCore(t, cluster)
	err = standbyClient().Sys().StepDown()
	require.NoError(t, err)
	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)
	activeAfterStepDown := testhelpers.DeriveActiveCore(t, cluster)
	require.NotEqual(t, activeBeforeStepDown.NodeID, activeAfterStepDown.NodeID, "expected different active after step-down")
}
