// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package manager_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"text/template"

	"github.com/hashicorp/consul-template/config"
	"github.com/hashicorp/consul-template/manager"
)

// ExampleCustomFuncMap demonstrates a minimum [consul-template/manager]
// configuration and supply custom templates to consul-template's internal
// [text/template] based renderer.
//
// It is not comprehensive and does not demonstrate the dependencies, polling,
// and rerendering features available in the manager
func Example_customFuncMap() {

	// Consul-template uses the standard logger, which needs to be silenced
	// in this example
	log.SetOutput(io.Discard)

	// Create a simple function to add to CT
	greet := func(n string) string { return "Hello, " + n + "!" }
	fm := template.FuncMap{"greet": greet}

	// Define a template that uses the new function
	tmpl := `{{greet "World"}}`

	// Make a destination path to write the rendered template to
	outPath := path.Join(os.TempDir(), "tmpl.out") // Use the temp dir
	defer os.RemoveAll(outPath)                    // Defer the file cleanup

	// Create a TemplateConfig
	tc1 := config.DefaultTemplateConfig() // Start with the default configuration
	tc1.ExtFuncMap = fm                   // Use the ExtFuncMap to add greet
	tc1.Contents = &tmpl                  // Add the template to the configuration
	tc1.Destination = &outPath            // Set the output destination
	tc1.Finalize()                        // Finalize the template config

	// Create the (consul-template) Config
	cfg := config.DefaultConfig()                // Start with default configuration
	cfg.Once = true                              // Perform a one-shot render
	cfg.Templates = &config.TemplateConfigs{tc1} // Add the template created earlier
	cfg.Finalize()                               // Finalize the consul-template configuration

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
	// Hello, World!
}
