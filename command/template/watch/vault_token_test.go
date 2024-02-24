// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/consul-template/config"
	dep "github.com/hashicorp/consul-template/dependency"
	"github.com/hashicorp/vault/api"
)

// approle auto-auth setup in watch_test.go, TestMain()
func TestVaultTokenWatcher(t *testing.T) {
	// Don't set the below to run in parallel. They mess with the single
	// running vault's permissions.
	t.Run("noop", func(t *testing.T) {
		conf := config.DefaultVaultConfig()
		watcher, err := VaultTokenWatcher(testClients, conf, nil)
		if err != nil {
			t.Error(err)
		}
		defer watcher.Stop()
		select {
		case err := <-watcher.ErrCh():
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			return
		}
	})

	t.Run("fixed_token", func(t *testing.T) {
		testClients.Vault().SetToken(vaultToken)
		conf := config.DefaultVaultConfig()
		token := vaultToken
		conf.Token = &token
		watcher, err := VaultTokenWatcher(testClients, conf, nil)
		if err != nil {
			t.Error(err)
		}
		defer watcher.Stop()
		if watcher != nil {
			t.Error("watcher should be nil")
		}
		if testClients.Vault().Token() != vaultToken {
			t.Error("Token should be " + vaultToken)
		}
	})

	t.Run("secretwrapped_token", func(t *testing.T) {
		testClients.Vault().SetToken(vaultToken)
		conf := config.DefaultVaultConfig()
		data, err := json.Marshal(&api.SecretWrapInfo{Token: vaultToken})
		if err != nil {
			t.Error(err)
		}
		jsonToken := string(data)
		conf.Token = &jsonToken
		watcher, err := VaultTokenWatcher(testClients, conf, nil)
		if err != nil {
			t.Error(err)
		}
		defer watcher.Stop()
		if testClients.Vault().Token() != vaultToken {
			t.Error("Token should be " + vaultToken)
		}
	})

	t.Run("tokenfile", func(t *testing.T) {
		// setup
		testClients.Vault().SetToken(vaultToken)
		tokenfile := runVaultAgent(testClients, tokenRoleId)
		defer func() {
			testClients.Vault().SetToken(vaultToken)
			os.Remove(tokenfile)
		}()
		conf := config.DefaultVaultConfig()
		token := vaultToken
		conf.Token = &token
		conf.VaultAgentTokenFile = &tokenfile
		// test data
		doneCh := make(chan struct{})
		watcher, err := VaultTokenWatcher(testClients, conf, doneCh)
		if err != nil {
			t.Error(err)
		}
		defer watcher.Stop()
		// tests
		select {
		case <-time.After(50 * time.Millisecond):
			// XXX remove this timer in hashicat port
			doneCh <- struct{}{}
		case err := <-watcher.ErrCh():
			t.Error(err)
		}

		if testClients.Vault().Token() == vaultToken {
			t.Error("Token should not be " + vaultToken)
		}
	})

	t.Run("renew", func(t *testing.T) {
		// exercise the renewer: the action is all inside the vault api
		// calls and vault so there's little to check.. so we just try
		// to call it and make sure it doesn't error
		testClients.Vault().SetToken(vaultToken)
		renew := true
		_, err := testClients.Vault().Auth().Token().Create(
			&api.TokenCreateRequest{
				ID:        "b_token",
				TTL:       "1m",
				Renewable: &renew,
			})
		if err != nil {
			t.Error(err)
		}
		conf := config.DefaultVaultConfig()
		token := "b_token"
		conf.Token = &token //
		conf.RenewToken = &renew
		watcher, err := VaultTokenWatcher(testClients, conf, nil)
		if err != nil {
			t.Error(err)
		}
		defer watcher.Stop()

		select {
		case err := <-watcher.ErrCh():
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Millisecond * 100):
			// give it a chance to throw an error
		}
	})
}

func TestVaultTokenRefreshToken(t *testing.T) {
	watcher := NewWatcher(&NewWatcherInput{
		Clients: testClients,
	})
	// force watcher to be synchronous so we can control test flow
	watcher.dataCh = make(chan *View) // no buffer
	wrapinfo := api.SecretWrapInfo{
		Token: "btoken",
	}
	b, _ := json.Marshal(wrapinfo)
	type testcase struct {
		name, raw_token, exp_token string
	}
	vault := testClients.Vault()
	testcases := []testcase{
		{name: "noop", raw_token: "foo", exp_token: "foo"},
		{name: "spaces", raw_token: " foo ", exp_token: "foo"},
		{name: "secretwrap", raw_token: string(b), exp_token: "btoken"},
	}
	for i, tc := range testcases {
		tc := tc // avoid for-loop pointer wart
		name := fmt.Sprintf("%d_%s", i, tc.name)
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			dCh := make(chan struct{})
			watchLoop, err := watchTokenFile(watcher, "", "XXX", false, dCh)
			if err != nil {
				t.Error(err)
			}
			wg.Add(1)
			go func() {
				watchLoop()
				wg.Done()
			}()
			fd := fakeDep{name: name}
			watcher.dataCh <- &View{dependency: fd, data: tc.raw_token}
			close(dCh) // close doneCh to stop watchLoop
			wg.Wait()
			if vault.Token() != tc.exp_token {
				t.Errorf("bad token, expected: '%s', received '%s'",
					tc.exp_token, tc.raw_token)
			}
		})
	}
	watcher.Stop()
}

// When vault-agent uses the wrap_ttl option it writes a json blob instead of
// a raw token. This verifies it will extract the token from that when needed.
// It doesn't test unwrap. The integration test covers that for now.
func TestVaultTokenGetToken(t *testing.T) {
	t.Run("table_test", func(t *testing.T) {
		wrapinfo := api.SecretWrapInfo{
			Token: "btoken",
		}
		b, _ := json.Marshal(wrapinfo)
		testcases := []struct{ in, out string }{
			{in: "", out: ""},
			{in: "atoken", out: "atoken"},
			{in: string(b), out: "btoken"},
		}
		for _, tc := range testcases {
			dummy := &setTokenFaker{}
			token, _ := unpackToken(dummy, tc.in, false)
			if token != tc.out {
				t.Errorf("unpackToken, wanted: '%v', got: '%v'", tc.out, token)
			}
		}
	})
	t.Run("unwrap_test", func(t *testing.T) {
		vault := testClients.Vault()
		vault.SetToken(vaultToken)
		vault.SetWrappingLookupFunc(func(operation, path string) string {
			if path == "auth/token/create" {
				return "30s"
			}
			return ""
		})
		defer vault.SetWrappingLookupFunc(nil)

		secret, err := vault.Auth().Token().Create(&api.TokenCreateRequest{
			Lease: "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		unwrap := true
		wrappedToken := secret.WrapInfo.Token
		token, err := unpackToken(vault, wrappedToken, unwrap)
		if err != nil {
			t.Fatal(err)
		}
		if token == wrappedToken {
			t.Errorf("tokens should not match")
		}
	})
}

type setTokenFaker struct {
	Token string
}

func (t *setTokenFaker) SetToken(token string) {}
func (t *setTokenFaker) Logical() *api.Logical { return nil }

var _ dep.Dependency = (*fakeDep)(nil)

type fakeDep struct{ name string }

func (d fakeDep) String() string { return d.name }
func (d fakeDep) CanShare() bool { return false }
func (d fakeDep) Stop()          {}
func (d fakeDep) Type() dep.Type { return dep.TypeConsul }
func (d fakeDep) Fetch(*dep.ClientSet, *dep.QueryOptions) (interface{}, *dep.ResponseMetadata, error) {
	return d.name, nil, nil
}
