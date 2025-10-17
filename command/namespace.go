// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*NamespaceCommand)(nil)

type NamespaceCommand struct {
	*BaseCommand
}

func (c *NamespaceCommand) Synopsis() string {
	return "Interact with namespaces"
}

func (c *NamespaceCommand) Help() string {
	helpText := `
Usage: bao namespace <subcommand> [options] [args]

  This command groups subcommands for interacting with OpenBao namespaces.
  These subcommands operate in the context of the namespace that the
  currently logged in token belongs to.

  List enabled child namespaces:

      $ bao namespace list

  List enabled child namespaces recursively:

      $ bao namespace scan

  Look up an existing namespace:

      $ bao namespace lookup

  Create a new namespace:

      $ bao namespace create

  Patch an existing namespace:

      $ bao namespace patch

  Delete an existing namespace:

      $ bao namespace delete

  Lock the API for an existing namespace:

      $ bao namespace lock

  Unlock the API for an existing namespace:

      $ bao namespace unlock

  Seal the namespace:  
  
      $ bao namespace seal 

  Unseal the namespace:

      $ bao namespace unseal

  Generate the root token for a sealable namespace:

      $ bao namespace generate-root

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *NamespaceCommand) Run(args []string) int {
	return cli.RunResultHelp
}
