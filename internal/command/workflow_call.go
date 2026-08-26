// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowCallCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowCallCommand)(nil)
)

type WorkflowCallCommand struct {
	*BaseCommand

	flagUnauthed bool

	testStdin io.Reader // for tests
}

func (c *WorkflowCallCommand) Synopsis() string {
	return "Call a workflow"
}

func (c *WorkflowCallCommand) Help() string {
	helpText := `
Usage: bao workflow call [options] PATH [DATA K=V...]

  Calls a OpenBao workflow, allowing for input data if needed.
  If a workflow doesn't require authentification, it can be called with the unauthed flag.

  Data is specified as "key=value" pairs. If the value begins with an "@", then
  it is loaded from a file. If the value is "-", OpenBao will read the value from
  stdin.

  Call a workflow:

      $ bao workflow call my-workflow

  Call a workflow without authentificaiton:

      $ bao workflow call -unauthed my-workflow

  Call a workflow with input variables:

      $ bao workflow call my-workflow username=tester

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowCallCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:       "unauthed",
		Target:     &c.flagUnauthed,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage:      "Call a unauthed workflow",
	})

	return set
}

func (c *WorkflowCallCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *WorkflowCallCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowCallCommand) Run(args []string) int {
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
	}

	// Pull our fake stdin if needed
	stdin := io.Reader(os.Stdin)
	if c.testStdin != nil {
		stdin = c.testStdin
	}
	if c.flagNonInteractive {
		stdin = bytes.NewReader(nil)
	}

	path := strings.TrimSpace(strings.ToLower(sanitizePath(args[0])))

	data, err := parseArgsData(stdin, args[1:])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to parse K=V data: %s", err))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	secret, err := client.Sys().CallWorkflow(context.Background(), path, data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error calling workflow at path %s: %s", path, err))
		if secret != nil {
			OutputSecret(c.UI, secret)
		}
		return 2
	}
	if secret == nil {
		// Don't output anything unless using the "table" format
		if Format(c.UI) == "table" {
			c.UI.Info(fmt.Sprintf("Success! Called workflow: %s", path))
		}
		return 0
	}

	if c.flagField != "" {
		return PrintRawField(c.UI, secret, c.flagField)
	}

	return OutputSecret(c.UI, secret)
}
