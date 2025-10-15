// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceKeyStatusCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceKeyStatusCommand)(nil)
)

type NamespaceKeyStatusCommand struct {
	*BaseCommand
}

func (c *NamespaceKeyStatusCommand) Synopsis() string {
	return "Provides information about the active encryption key of a namespace"
}

func (c *NamespaceKeyStatusCommand) Help() string {
	helpText := `
Usage: bao namespace key-status [options] PATH

  Provides information about the namespace active encryption key.
  Specifically, the current key term and the key installation time.

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceKeyStatusCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
}

func (c *NamespaceKeyStatusCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *NamespaceKeyStatusCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceKeyStatusCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) < 1 {
		c.UI.Error("Not enough arguments (expected 1, got 0)")
		return 1
	}
	if len(args) > 1 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	status, err := client.Sys().NamespaceKeyStatus(args[0])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading key status: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		c.UI.Output(printKeyStatus(status))
		return 0
	default:
		return OutputData(c.UI, status)
	}
}
