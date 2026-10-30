// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowInfoCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowInfoCommand)(nil)
)

type WorkflowInfoCommand struct {
	*BaseCommand

	flagUnauthed bool
}

func (c *WorkflowInfoCommand) Synopsis() string {
	return "Prints the execution relevant information of a workflow"
}

func (c *WorkflowInfoCommand) Help() string {
	helpText := `
Usage: bao workflow info [options] PATH

  Prints the information needed to call a OpenBao workflow under the given
  path: its declared inputs, output headers and output data keys.
  Unlike "workflow read", this does not require read access to the workflow's full definition.

  Show info for the workflow "test-workflow":

      $ bao workflow info test-workflow

  Show info for a workflow that allows unauthenticated calls:

      $ bao workflow info -unauthed test-workflow

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowInfoCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:       "unauthed",
		Target:     &c.flagUnauthed,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage:      "Look up an unauthed workflow",
	})

	return set
}

func (c *WorkflowInfoCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultWorkflows()
}

func (c *WorkflowInfoCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowInfoCommand) Run(args []string) int {
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

	path := strings.TrimSpace(strings.ToLower(sanitizePath(args[0])))
	info, err := client.Sys().DescribeWorkflow(context.Background(), path, c.flagUnauthed)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading workflow info under path %s: %s", path, err))
		return 2
	}
	if info == nil {
		c.UI.Error(fmt.Sprintf("No workflow found in path %s", path))
		return 2
	}

	data := map[string]any{
		"path":             info.Path,
		"description":      info.Description,
		"inputs":           info.Inputs,
		"output_headers":   info.OutputHeaders,
		"output_data_keys": info.OutputDataKeys,
	}
	if c.flagField != "" {
		return PrintRawField(c.UI, data, c.flagField)
	}
	return OutputData(c.UI, data)
}
