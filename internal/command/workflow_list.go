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
	_ cli.Command             = (*WorkflowListCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowListCommand)(nil)
)

type WorkflowListCommand struct {
	*BaseCommand
}

func (c *WorkflowListCommand) Synopsis() string {
	return "Prints all workflows"
}

func (c *WorkflowListCommand) Help() string {
	helpText := `
Usage: bao workflow list [options]

  This command outputs a list of all workflows created.

  Fetch list of all workflows:

      $ bao workflow list

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowListCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
}

func (c *WorkflowListCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *WorkflowListCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowListCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	switch {
	case len(args) > 0:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	workflows, err := client.Sys().ListWorkflows()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading workflows: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		out := []string{"Path"}
		out = append(out, workflows...)
		c.UI.Output(tableOutput(out, nil))
		return 0
	default:
		return OutputData(c.UI, workflows)
	}
}
