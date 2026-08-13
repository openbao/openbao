// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*LeaseCommand)(nil)

type LeaseCommand struct {
	*BaseCommand
}

func (c *LeaseCommand) Synopsis() string {
	return "Interact with leases"
}

func (c *LeaseCommand) Help() string {
	helpText := `
Usage: bao lease <subcommand> [options] [args]

  This command groups subcommands for interacting with leases. Users can revoke
  or renew leases.

  Renew a lease:

      $ bao lease renew database/creds/readonly/2f6a614c...

  Revoke a lease:

      $ bao lease revoke database/creds/readonly/2f6a614c...
`

	return strings.TrimSpace(helpText)
}

func (c *LeaseCommand) Run(args []string) int {
	return cli.RunResultHelp
}
