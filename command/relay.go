// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*RelayCommand)(nil)

type RelayCommand struct {
	*BaseCommand
}

func (c *RelayCommand) Synopsis() string {
	return "Manage the hub-and-spoke relay for remote database plugins"
}

func (c *RelayCommand) Help() string {
	helpText := `
Usage: bao relay <subcommand> [options] [args]

  This command groups subcommands for operating the hub-and-spoke relay used
  by remote database plugins. Here are a few examples:

  Initialize the hub for spoke joins and print a join command:

      $ bao relay init

  Join a spoke to the hub using a bootstrap token:

      $ bao relay join

  Run the spoke daemon:

      $ bao relay run

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *RelayCommand) Run(args []string) int {
	return cli.RunResultHelp
}
