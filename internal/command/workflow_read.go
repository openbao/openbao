// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/sdk/v2/helper/structtomap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowReadCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowReadCommand)(nil)
)

type WorkflowReadCommand struct {
	*BaseCommand
}

func (c *WorkflowReadCommand) Synopsis() string {
	return "Prints the information about a workflow"
}

func (c *WorkflowReadCommand) Help() string {
	helpText := `
Usage: bao workflow read [options] [PATH]

  Prints the content and metadata of a OpenBao workflow under the given path.
  If the policy does not exist, an error is returned.

  Read the workflow "test-workflow":

      $ bao workflow read test-workflow

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowReadCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
}

func (c *WorkflowReadCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultWorkflows()
}

func (c *WorkflowReadCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowReadCommand) Run(args []string) int {
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

	path := strings.ToLower(strings.TrimSpace(args[0]))
	workflowResp, err := client.Sys().GetWorkflow(path)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading workflow under path %s: %s", path, err))
		return 2
	}
	if workflowResp == nil {
		c.UI.Error(fmt.Sprintf("No workflow found in path %s", path))
		return 2
	}

	data := structtomap.Map(workflowResp)
	if c.flagField != "" {
		return PrintRawField(c.UI, data, c.flagField)
	}
	return OutputData(c.UI, data)
}
