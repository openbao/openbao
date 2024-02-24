// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package manager

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	"github.com/openbao/openbao/command/template/config"
	dep "github.com/openbao/openbao/command/template/dependency"
	"github.com/openbao/openbao/command/template/test"
)

var testClients *dep.ClientSet

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	tb := &test.TestingTB{}

	clients, err := NewClientSet(&config.Config{
		Vault: config.DefaultVaultConfig(),
	})
	if err != nil {
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
				panic(r)
			}
		}()

		exitCh <- m.Run()
	}()

	exit := <-exitCh

	tb.DoCleanup()
	os.Exit(exit)
}
