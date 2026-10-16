// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*WorkflowCommand)(nil)

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
  Users can list, read, write, edit, delete, call and inspect workflows.

  List all workflows:

      $ bao workflow list

  Read the workflow named "my-workflow":

      $ bao workflow read my-workflow

  Show execution relevant information of "my-workflow" without requiring read
  access to its full definition:

      $ bao workflow info my-workflow

  Create or update a workflow named "my-workflow" from local file:

      $ bao workflow write my-workflow ./my-workflow.hcl

  Edit a workflow named "my-workflow" inside your local editor:

      $ bao workflow edit my-workflow

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
