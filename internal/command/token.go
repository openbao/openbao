// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*TokenCommand)(nil)

type TokenCommand struct {
	*BaseCommand
}

func (c *TokenCommand) Synopsis() string {
	return "Interact with tokens"
}

func (c *TokenCommand) Help() string {
	helpText := `
Usage: bao token <subcommand> [options] [args]

  This command groups subcommands for interacting with tokens. Users can
  create, lookup, renew, and revoke tokens.

  Create a new token:

      $ bao token create

  Revoke a token:

      $ bao token revoke 96ddf4bc-d217-f3ba-f9bd-017055595017

  Renew a token:

      $ bao token renew 96ddf4bc-d217-f3ba-f9bd-017055595017

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *TokenCommand) Run(args []string) int {
	return cli.RunResultHelp
}
