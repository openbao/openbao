// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/pluginutil/oci"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*PluginInitCommand)(nil)
	_ cli.CommandAutocomplete = (*PluginInitCommand)(nil)
)

type PluginInitCommand struct {
	*BaseCommand

	flagConfigs   []string
	flagDirectory string
	flagTimeout   time.Duration
}

func (c *PluginInitCommand) Synopsis() string {
	return "Initialize and download OCI-based plugins"
}

func (c *PluginInitCommand) Help() string {
	helpText := `
Usage: bao plugin init [options]

  This command reads the plugin configuration from the server config files,
  downloads the specified OCI images, and extracts the contained plugin
  binaries. This command does not automatically register the plugin to the
  server, which is handled automatically via the server on startup and SIGHUP
  if 'plugin_auto_register=true' is set in the configuration file. When the
  server's configuration includes 'plugin_auto_download=true', plugins will be
  automatically downloaded on server startup and on SIGHUP.

  Initialize plugins using configuration files:

      $ bao plugin init -config=/path/to/openbao.hcl

  Initialize plugins with multiple configuration files:

      $ bao plugin init -config=/etc/openbao -config=/opt/openbao/extra.hcl

  Initialize plugins to a specific directory:

      $ bao plugin init -config=/path/to/config.hcl -directory=/opt/openbao/plugins

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *PluginInitCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
			complete.PredictDirs("*"),
		),
		Usage: "Path to a configuration file or directory of configuration " +
			"files. This flag can be specified multiple times to load multiple " +
			"configurations. If the path is a directory, all files which end in " +
			".hcl or .json are loaded.",
	})

	f.StringVar(&StringVar{
		Name:    "directory",
		Target:  &c.flagDirectory,
		Default: "",
		Usage: "Directory where plugins should be downloaded. If not specified, " +
			"uses the plugin_directory from the configuration file.",
	})

	f.DurationVar(&DurationVar{
		Name:    "timeout",
		Target:  &c.flagTimeout,
		Default: 300 * time.Second,
		Usage:   "Global timeout for downloading all plugins.",
	})

	return set
}

func (c *PluginInitCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *PluginInitCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PluginInitCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if len(f.Args()) > 0 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(f.Args())))
		return 1
	}

	return c.runPluginInit()
}

func (c *PluginInitCommand) runPluginInit() int {
	// Require config flags to be specified
	if len(c.flagConfigs) == 0 {
		c.UI.Error("No configuration specified. Use -config flag to specify configuration files or directories.")
		return 1
	}

	// Parse configuration using the same logic as the server command
	config, configErrors, err := c.ParseServerConfig(c.flagConfigs)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing configuration: %v", err))
		return 1
	}

	// Display configuration errors if any and exit
	for _, configError := range configErrors {
		c.UI.Error(configError.String())
	}

	if len(configErrors) > 0 {
		return 1
	}

	// Determine plugin directory
	pluginDir := c.flagDirectory
	if pluginDir == "" {
		pluginDir = config.PluginDirectory
	}
	if pluginDir == "" {
		c.UI.Error("No plugin directory specified. Use -directory flag or set plugin_directory in config.")
		return 1
	}

	// Check if plugins are configured
	if len(config.Plugins) == 0 {
		c.UI.Error("No OCI plugins configured in the configuration files.")
		return 1
	}

	hclog.Default().Info(fmt.Sprintf("Plugin directory: %s", pluginDir))
	hclog.Default().Info(fmt.Sprintf("Found %d OCI plugin(s) in configuration", len(config.Plugins)))

	// Ensure plugin directory exists
	if err = os.MkdirAll(pluginDir, 0o755); err != nil {
		hclog.Default().Error(fmt.Sprintf("Failed to create plugin directory: %v", err))
		return 1
	}

	// Initialize plugins using the existing reconciliation logic
	return c.reconcilePlugins(config, pluginDir)
}

func (c *PluginInitCommand) reconcilePlugins(config *server.Config, pluginDir string) int {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.flagTimeout)
	defer cancel()

	// Create OCI plugin downloader using the shared package
	downloader := oci.NewPluginDownloader(pluginDir, config, hclog.Default())

	err := downloader.ReconcilePlugins(ctx)
	if err != nil {
		hclog.Default().Error(fmt.Sprintf("Error reconciling plugins: %s", err))
		return 1
	}

	return 0
}
