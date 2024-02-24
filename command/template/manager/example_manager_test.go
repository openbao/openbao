// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package manager_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"github.com/hashicorp/consul-template/config"
	"github.com/hashicorp/consul-template/manager"
)

// This example demonstrates a minimum configuration to create, configure, and
// use a consul-template/manager from code. It is not comprehensive and does not
// demonstrate the dependencies, polling, and rerendering features available in
// the manager
func Example() {
	// Consul-template uses the standard logger, which needs to be silenced
	// in this example
	log.SetOutput(io.Discard)

	// Define a template
	tmpl := `{{ "foo\nbar\n" | split "\n" | toJSONPretty }}`

	// Make a destination path to write the rendered template to
	outPath := path.Join(os.TempDir(), "tmpl.out") // Use the temp dir
	defer os.RemoveAll(outPath)                    // Defer the file cleanup

	// Create a TemplateConfig
	tCfg := config.DefaultTemplateConfig() // Start with the default configuration
	tCfg.Contents = &tmpl                  // Add the template to the configuration
	tCfg.Destination = &outPath            // Set the output destination
	tCfg.Finalize()                        // Finalize the template config

	// Create the (consul-template) Config
	cfg := config.DefaultConfig()                 // Start with default configuration
	cfg.Once = true                               // Perform a one-shot render
	cfg.Templates = &config.TemplateConfigs{tCfg} // Add the template created earlier
	cfg.Finalize()                                // Finalize the consul-template configuration

	// Instantiate a runner with the config and with `dry` == false
	runner, err := manager.NewRunner(cfg, false)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		return
	}

	go runner.Start() // The runner blocks, so must be started in a goroutine
	defer runner.Stop()

	select {
	// When the runner is successfully done, it will emit a message on DoneCh
	case <-runner.DoneCh:
		break

	// When the runner encounters an error, it will emit an error on ErrCh and
	// then return.
	case err := <-runner.ErrCh:
		fmt.Printf("[ERROR] %s\n", err.Error())
		return
	}

	// Read the rendered template from disk
	if b, e := os.ReadFile(outPath); e == nil {
		fmt.Println(string(b))
	} else {
		fmt.Printf("[ERROR] %s\n", err.Error())
		return
	}
	// Output:
	// [
	//   "foo",
	//   "bar"
	// ]
}
