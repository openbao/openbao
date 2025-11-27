// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	bplugin "github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/benchhelpers"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/openbao/sdk/v2/plugin/mock"
	"github.com/openbao/openbao/vault"
)

func getPluginClusterAndCore(t testing.TB, logger log.Logger) (*vault.TestCluster, *vault.TestClusterCore) {
	inm, err := inmem.NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	inmha, err := inmem.NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	coreConfig := &vault.CoreConfig{
		Physical:   inm,
		HAPhysical: inmha.(physical.HABackend),
		LogicalBackends: map[string]logical.Factory{
			"plugin": bplugin.Factory,
		},
	}

	cluster := vault.NewTestCluster(benchhelpers.TBtoT(t), coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
		Logger:      logger.Named("testclusteroptions"),
	})
	cluster.Start()

	cores := cluster.Cores
	core := cores[0]

	os.Setenv(pluginutil.PluginCACertPEMEnv, cluster.CACertPEMFile)

	vault.TestWaitActive(benchhelpers.TBtoT(t), core.Core)
	vault.TestAddTestPlugin(benchhelpers.TBtoT(t), core.Core, "mock-plugin", consts.PluginTypeSecrets, "", "TestPlugin_PluginMain", []string{}, "")

	// Mount the mock plugin
	err = core.Client.Sys().Mount("mock", &api.MountInput{
		Type: "mock-plugin",
	})
	if err != nil {
		t.Fatal(err)
	}

	return cluster, core
}

func TestPlugin_PluginMain(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}

	caPEM := api.ReadBaoVariable(pluginutil.PluginCACertPEMEnv)
	if caPEM == "" {
		t.Fatal("CA cert not passed in")
	}

	args := []string{"--ca-cert=" + caPEM}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(args)

	factoryFunc := mock.FactoryType(logical.TypeLogical)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: factoryFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("Why are we here")
}

func TestPlugin_MockList(t *testing.T) {
	logger := log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
	})
	cluster, core := getPluginClusterAndCore(t, logger)
	defer cluster.Cleanup()

	_, err := core.Client.Logical().Write("mock/kv/foo", map[string]interface{}{
		"value": "baz",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err := core.Client.Logical().List("mock/kv/")
	if err != nil {
		t.Fatal(err)
	}
	if keys.Data["keys"].([]interface{})[0].(string) != "foo" {
		t.Fatal(keys)
	}

	_, err = core.Client.Logical().Write("mock/kv/zoo", map[string]interface{}{
		"value": "baz",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err = core.Client.Logical().List("mock/kv/")
	if err != nil {
		t.Fatal(err)
	}
	if keys.Data["keys"].([]interface{})[0].(string) != "foo" || keys.Data["keys"].([]interface{})[1].(string) != "zoo" {
		t.Fatal(keys)
	}
}

func TestPlugin_MockRawResponse(t *testing.T) {
	logger := log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
	})
	cluster, core := getPluginClusterAndCore(t, logger)
	defer cluster.Cleanup()

	resp, err := core.Client.Logical().ReadRaw("mock/raw")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body[:]) != "Response" {
		t.Fatal("bad body")
	}

	if resp.StatusCode != 200 {
		t.Fatal("bad status")
	}
}

func TestPlugin_GetParams(t *testing.T) {
	logger := log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
	})
	cluster, core := getPluginClusterAndCore(t, logger)
	defer cluster.Cleanup()

	_, err := core.Client.Logical().Write("mock/kv/foo", map[string]interface{}{
		"value": "baz",
	})
	if err != nil {
		t.Fatal(err)
	}

	params := url.Values{"version": []string{"12"}}
	resp, err := core.Client.Logical().ReadRawWithData("mock/kv/foo", params)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]interface{}{
		"value":   "baz",
		"version": json.Number("12"),
	}

	if !reflect.DeepEqual(secret.Data, expected) {
		t.Fatal(secret.Data)
	}
}
