// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"io"
	"log"
	"os"
	"testing"

	"github.com/openbao/openbao/command/template/test"
)

func TestMain(m *testing.M) {
	tb := &test.TestingTB{}
	log.SetOutput(io.Discard)

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
