// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowDeleteCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowDeleteCommand)(nil)
)

type WorkflowDeleteCommand struct {
	*BaseCommand
}

func (c *WorkflowDeleteCommand) Synopsis() string {
	return "Deletes a workflow by path"
}

func (c *WorkflowDeleteCommand) Help() string {
	helpText := `
Usage: bao workflow delete [options] PATH

  Deletes the workflow under the given PATH in the OpenBao server.

  Delete the workflow named "my-workflow":

      $ bao workflow delete my-workflow

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowDeleteCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP)
}

func (c *WorkflowDeleteCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultWorkflows()
}

func (c *WorkflowDeleteCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowDeleteCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	switch {
	case len(args) < 1:
		c.UI.Error(fmt.Sprintf("Not enough arguments (expected 1, got %d)", len(args)))
		return 1
	case len(args) > 1:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	path := strings.TrimSpace(strings.ToLower(args[0]))
	if err := client.Sys().DeleteWorkflow(path); err != nil {
		c.UI.Error(fmt.Sprintf("Error deleting workflow at path %s: %s", path, err))
		return 2
	}

	c.UI.Output(fmt.Sprintf("Success! Deleted workflow at path: %s", path))
	return 0
}
