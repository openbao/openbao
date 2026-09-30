// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/helper/pluginutil/oci"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*PluginPruneCommand)(nil)
	_ cli.CommandAutocomplete = (*PluginPruneCommand)(nil)
)

type PluginPruneCommand struct {
	*BaseCommand

	flagConfigs   []string
	flagDirectory string
}

func (c *PluginPruneCommand) Synopsis() string {
	return "Remove unused OCI-based plugins from the plugin directory"
}

func (c *PluginPruneCommand) Help() string {
	helpText := `
Usage: bao plugin prune [options]

  This command reads plugin configuration from the given server configuration
  files and removes unused OCI-based plugins found in the given plugin directory
  but not referenced by the configuration from disk.

  This can be used to free disk space following plugin upgrades by removing the
  binaries of any prior versions. Plugins that were manually installed into the
  plugin directory are ignored and left in place.

  Prune plugins using a configuration file:

      $ bao plugin prune -config=/path/to/openbao.hcl

  Prune within a specific directory:

      $ bao plugin prune -config=/path/to/config.hcl -directory=/opt/openbao/plugins

  Load multiple configuration files:

      $ bao plugin prune -config=/etc/openbao -config=/opt/openbao/extra.hcl

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *PluginPruneCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		EnvVar: "BAO_CONFIG_PATH",
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
		Usage: "Directory where plugins should be removed. If not specified, " +
			"uses the plugin_directory from the configuration file.",
	})

	return set
}

func (c *PluginPruneCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *PluginPruneCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PluginPruneCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if len(f.Args()) > 0 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(f.Args())))
		return 1
	}

	if len(c.flagConfigs) == 0 {
		c.UI.Error("No configuration specified. Use the -config flag to specify configuration files or directories.")
		return 1
	}

	config, configErrors, err := c.ParseServerConfig(c.flagConfigs)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing configuration: %v", err))
		return 1
	}

	for _, configError := range configErrors {
		c.UI.Error(configError.String())
	}

	if len(configErrors) > 0 {
		return 1
	}

	pluginDir := c.flagDirectory
	if pluginDir == "" {
		pluginDir = config.PluginDirectory
	}
	if pluginDir == "" {
		c.UI.Error("No plugin directory specified. Use the -directory flag or set plugin_directory in config.")
		return 1
	}

	logger := hclog.Default()

	logger.Info(fmt.Sprintf("plugin directory: %s", pluginDir))
	logger.Info(fmt.Sprintf("found %d OCI plugin(s) in configuration", len(config.Plugins)))

	if _, err := os.Stat(pluginDir); errors.Is(err, os.ErrNotExist) {
		logger.Warn(fmt.Sprintf("plugin directory %q does not exist, exiting", pluginDir))
		return 0
	} else if err != nil {
		logger.Error(fmt.Sprintf("failed to stat plugin directory: %v", err))
		return 1
	}

	if err := oci.NewPluginDownloader(pluginDir, config, logger).Prune(); err != nil {
		logger.Error(fmt.Sprintf("error pruning plugins: %s", err))
		return 1
	}

	return 0
}
