// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceDeleteSealedCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceDeleteSealedCommand)(nil)
)

type NamespaceDeleteSealedCommand struct {
	*BaseCommand

	flagForce bool
}

func (c *NamespaceDeleteSealedCommand) Synopsis() string {
	return "Delete a sealed namespace"
}

func (c *NamespaceDeleteSealedCommand) Help() string {
	helpText := `
Usage: bao namespace delete-sealed [options] PATH

  Delete a sealed namespace by physically wiping its storage.

  Note that this requires the sudo capability and will not clean up external
  resources via lease deletion like standard namespace deletion does. Prefer the
  standard 'bao namespace delete' command unless the namespace is irrecoverable
  due to lost seal keys.

  The namespace deleted will be relative to the namespace provided in either
  the BAO_NAMESPACE environment variable or -namespace CLI flag.

  Delete a sealed namespace with no child namespaces:

      $ bao namespace delete-sealed ns1

  Delete a sealed namespace and recursively wipe its child namespaces:

      $ bao namespace delete-sealed -force ns1

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceDeleteSealedCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:    "force",
		Target:  &c.flagForce,
		Default: false,
		Usage: "Recursively delete all child namespaces of the sealed namespace. " +
			"Required when the namespace has children.",
	})

	return set
}

func (c *NamespaceDeleteSealedCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultNamespaces()
}

func (c *NamespaceDeleteSealedCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceDeleteSealedCommand) Run(args []string) int {
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

	namespacePath := strings.TrimSpace(args[0])

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	params := map[string][]string{}
	if c.flagForce {
		params["force"] = []string{"true"}
	}

	secret, err := client.Logical().DeleteWithData(
		fmt.Sprintf("sys/namespaces/%s/delete-sealed", namespacePath), params,
	)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error deleting sealed namespace: %s", err))
		return 2
	}

	if secret == nil || secret.Data == nil {
		if secret != nil {
			return OutputSecret(c.UI, secret)
		}
		c.UI.Warn("Requested namespace does not exist")
		return 0
	}

	if !strings.HasSuffix(namespacePath, "/") {
		namespacePath = namespacePath + "/"
	}

	for _, w := range secret.Warnings {
		c.UI.Warn(w)
	}
	c.UI.Output(fmt.Sprintf("Success! Namespace deletion scheduled: %s", namespacePath))
	return 0
}
