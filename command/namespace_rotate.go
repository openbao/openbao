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
	_ cli.Command             = (*NamespaceRotateCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceRotateCommand)(nil)
)

type NamespaceRotateCommand struct {
	*BaseCommand
}

func (c *NamespaceRotateCommand) Synopsis() string {
	return "Rotates the underlying namespace encryption key"
}

func (c *NamespaceRotateCommand) Help() string {
	helpText := `
Usage: bao namespace rotate [options] PATH

  Rotates the underlying namespace encryption key which is used to secure data
  written to the storage backend. This installs a new key in the keyring. This
  new key is used to encrypted new data, while older keys in the keyring are
  used to decrypt older data.

  Rotate namespace encryption key:

      $ bao namespace rotate PATH

  For a full list of examples, please see the documentation.

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceRotateCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
}

func (c *NamespaceRotateCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *NamespaceRotateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceRotateCommand) Run(args []string) int {
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

	err = client.Sys().NamespaceRotateKeyring(args[0])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error rotating keyring: %s", err))
		return 2
	}

	status, err := client.Sys().NamespaceKeyStatus(args[0])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading key status: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		c.UI.Output("Success! Rotated encryption key")
		c.UI.Output("")
		c.UI.Output(printKeyStatus(status))
		return 0
	default:
		return OutputData(c.UI, status)
	}
}
