// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceSealCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceSealCommand)(nil)
)

type NamespaceSealStatusCommand struct {
	*BaseCommand
}

func (c *NamespaceSealStatusCommand) Synopsis() string {
	return "Prints the namespace seal status"
}

func (c *NamespaceSealStatusCommand) Help() string {
	helpText := `
Usage: bao namespace seal-status [options] PATH

  This command reports whether the namespace is sealed and provides related
  seal information. A sealed namespace does not respond to operations until it
  is unsealed. If a namespace is not sealable, this command returns an error.

  Retrieve the namespace seal status:

      $ bao namespace seal-status ns1

  Retrieve the seal status of a nested namespace:

      $ bao namespace seal-status -ns ns1 ns2

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceSealStatusCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP)
}

func (c *NamespaceSealStatusCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultNamespaces()
}

func (c *NamespaceSealStatusCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceSealStatusCommand) Run(args []string) int {
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
	status, err := client.Sys().NamespaceSealStatus(namespacePath)
	if err != nil || status == nil {
		c.UI.Error(fmt.Sprintf("Error reading seal status: %s", err))
		return 2
	}

	return OutputData(c.UI, api.SealStatusResponse{
		Type:        status.Type,
		Initialized: status.Initialized,
		Sealed:      status.Sealed,
		T:           status.T,
		N:           status.N,
		Progress:    status.Progress,
		Nonce:       status.Nonce,
	})
}
