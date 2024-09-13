// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*OperatorRaftCommand)(nil)

type OperatorRaftCommand struct {
	*BaseCommand
}

func (c *OperatorRaftCommand) Synopsis() string {
	return "Interact with Vault's raft storage backend"
}

func (c *OperatorRaftCommand) Help() string {
	helpText := `
Usage: bao operator raft <subcommand> [options] [args]

  This command groups subcommands for operators interacting with the Vault raft
  storage backend. Most users will not need to interact with these commands. Here
  are a few examples of the raft operator commands:

  Joins a node to the raft cluster:

      $ bao operator raft join https://127.0.0.1:8200

  Returns the set of raft peers:

      $ bao operator raft list-peers

  Removes a node from the raft cluster:

      $ bao operator raft remove-peer

  Restores and saves snapshots from the raft cluster:

      $ bao operator raft snapshot save out.snap

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *OperatorRaftCommand) Run(args []string) int {
	return cli.RunResultHelp
}
