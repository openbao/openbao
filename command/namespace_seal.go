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
	_ cli.Command             = (*NamespaceSealCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceSealCommand)(nil)
)

type NamespaceSealCommand struct {
	*BaseCommand
}

func (c *NamespaceSealCommand) Synopsis() string {
	return "Seals the namespace"
}

func (c *NamespaceSealCommand) Help() string {
	helpText := `
Usage: bao namespace seal [options] PATH

  Seals the OpenBao namespace. Sealing tells the namespace to stop responding
  to any operations until it is unsealed. When sealed, the namespace
  discards its in-memory root key used data encryption, so it is physically
  blocked from responding to operations while sealed.

  If an unseal is in progress, sealing the namespace will reset the unsealing
  process. Users will have to re-enter their portions of the root key again.

  This command does nothing if the namespace is already sealed.

  Seal the namespace:

      $ bao namespace seal

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceSealCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP)
}

func (c *NamespaceSealCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultNamespaces()
}

func (c *NamespaceSealCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceSealCommand) Run(args []string) int {
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

	namespacePath := strings.TrimSpace(args[0])
	if err = client.Sys().SealNamespace(namespacePath); err != nil {
		c.UI.Error(fmt.Sprintf("Error sealing: %s", err))
		return 2
	}

	c.UI.Output(fmt.Sprintf("Success! Namespace %q is sealed.", namespacePath))
	return 0
}
