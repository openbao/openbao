// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	dep "github.com/hashicorp/consul-template/dependency"
	"github.com/hashicorp/consul-template/test"
	"github.com/hashicorp/consul/sdk/testutil"
)

var (
	testConsul  *testutil.TestServer
	testClients *dep.ClientSet
)

func TestMain(m *testing.M) {
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
	log.SetOutput(io.Discard)

	clients := dep.NewClientSet()
	if err := clients.CreateConsulClient(&dep.CreateConsulClientInput{
		Address: testConsul.HTTPAddr,
	}); err != nil {
		testConsul.Stop()
		log.Fatal(err)
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
