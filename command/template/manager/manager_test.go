// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package manager

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/consul-template/config"
	dep "github.com/hashicorp/consul-template/dependency"
	"github.com/hashicorp/consul-template/template"
	"github.com/hashicorp/consul-template/test"
	"github.com/hashicorp/consul/sdk/testutil"
)

var (
	testConsul  *testutil.TestServer
	testClients *dep.ClientSet
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	tb := &test.TestingTB{}
	consul, err := testutil.NewTestServerConfigT(tb,
		func(c *testutil.TestServerConfig) {
			c.LogLevel = "warn"
			c.Stdout = io.Discard
			c.Stderr = io.Discard
		})
	if err != nil {
		log.Fatal(fmt.Errorf("failed to start consul server: %v", err))
	}
	testConsul = consul

	consulConfig := config.DefaultConsulConfig()
	consulConfig.Address = &testConsul.HTTPAddr
	clients, err := NewClientSet(&config.Config{
		Consul: consulConfig,
		Vault:  config.DefaultVaultConfig(),
		Nomad:  config.DefaultNomadConfig(),
	})
	if err != nil {
		testConsul.Stop()
		log.Fatal(fmt.Errorf("failed to start clients: %v", err))
	}
	testClients = clients

	exitCh := make(chan int, 1)
	func() {
		defer func() {
			// Attempt to recover from a panic and stop the server. If we don't stop
			// it, the panic will cause the server to remain running in the
			// background. Here we catch the panic and the re-raise it.
			if r := recover(); r != nil {
				testConsul.Stop()
				panic(r)
			}
		}()

		exitCh <- m.Run()
	}()

	exit := <-exitCh

	tb.DoCleanup()
	testConsul.Stop()
	os.Exit(exit)
}

func testDedupManager(t *testing.T, tmpls []*template.Template) *DedupManager {
	brain := template.NewBrain()
	dedupConfig := config.TestConfig(nil).Dedup
	dedup, err := NewDedupManager(dedupConfig, testClients, brain, tmpls)
	if err != nil {
		t.Fatal(err)
	}
	return dedup
}
