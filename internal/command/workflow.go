// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*TokenCommand)(nil)

type WorkflowCommand struct {
	*BaseCommand
}

func (c *WorkflowCommand) Synopsis() string {
	return "Interact with workflows"
}

func (c *WorkflowCommand) Help() string {
	helpText := `
Usage: bao workflow <subcommand> [options] [args]

  This command groups subcommands are for interacting with workflows.
  Users can list, read, write, delete and call workflows.

  List all workflows:

      $ bao workflow list

  Read the workflow named "my-workflow":

      $ bao workflow read my-workflow

  Create or update a workflow named "my-workflow" from local file:

      $ bao workflow write my-workflow ./my-workflow.hcl

  Delete the workflow named "my-workflow":

      $ bao workflow delete my-workflow

  Call the workflow named "my-workflow":

      $ bao workflow call my-workflow

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *WorkflowCommand) Run(args []string) int {
	return cli.RunResultHelp
}
