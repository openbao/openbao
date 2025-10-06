// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceUnsealCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceUnsealCommand)(nil)
)

type NamespaceUnsealCommand struct {
	*BaseCommand

	flagReset bool

	testOutput io.Writer // for tests
}

func (c *NamespaceUnsealCommand) Synopsis() string {
	return "Unseals the namespace"
}

func (c *NamespaceUnsealCommand) Help() string {
	helpText := `
Usage: bao namespace unseal [options] PATH [KEY]

  Unseals the OpenBao namespace. Provide a portion of the root key to unseal
  an OpenBao namespace. Namespaces cannot perform operations until they are
  unsealed. This command accepts a portion of the root key (an "unseal key").

  The unseal key can be supplied as an argument to the command, but this is
  not recommended as the unseal key will be available in your history:

      $ bao namespace unseal ns1 IXyR0OJnSFobekZMMCKCoVEpT7wI6l+USMzE3IcyDyo=

  Instead, run the command with no arguments and it will prompt for the key:

      $ bao namespace unseal ns1
      Key (will be hidden): IXyR0OJnSFobekZMMCKCoVEpT7wI6l+USMzE3IcyDyo=

  Optionally, you can reset the unseal progress, discarding any already
  provided unseal keyshares with a reset flag:

      $ bao namespace unseal --reset ns1

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceUnsealCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:       "reset",
		Aliases:    []string{},
		Target:     &c.flagReset,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage:      "Discard any previously entered keys to the unseal process.",
	})

	return set
}

func (c *NamespaceUnsealCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultNamespaces()
}

func (c *NamespaceUnsealCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceUnsealCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	var unsealKey string
	var namespacePath string

	args = f.Args()
	switch len(args) {
	case 0:
		c.UI.Error("Not enough arguments (expected 1-2, got 0)")
		return 1
	case 1:
		// We will prompt for the unseal key later
		namespacePath = strings.TrimSpace(args[0])
	case 2:
		namespacePath = strings.TrimSpace(args[0])
		unsealKey = strings.TrimSpace(args[1])
	default:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1-2, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	if c.flagReset {
		status, err := client.Sys().UnsealNamespace(
			&api.UnsealNamespaceRequest{
				Name:  namespacePath,
				Reset: true,
			},
		)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error resetting unseal process: %s", err))
			return 2
		}
		return OutputData(c.UI, SealStatusOutput{SealStatusResponse: api.SealStatusResponse{
			Type:        status.Type,
			Initialized: status.Initialized,
			Sealed:      status.Sealed,
			T:           status.T,
			N:           status.N,
			Progress:    status.Progress,
			Nonce:       status.Nonce,
		}})
	}

	if unsealKey == "" {
		if c.flagNonInteractive {
			c.UI.Error(wrapAtLength("Refusing to read from stdin with -non-interactive specified; specify unseal key as an argument to this command"))
			return 1
		}

		// Override the output
		writer := (io.Writer)(os.Stdout)
		if c.testOutput != nil {
			writer = c.testOutput
		}

		_, _ = fmt.Fprintf(writer, "Unseal Key (will be hidden): ")
		value, err := password.Read(os.Stdin)
		_, _ = fmt.Fprintf(writer, "\n")
		if err != nil {
			c.UI.Error(wrapAtLength(fmt.Sprintf("An error occurred attempting to "+
				"ask for an unseal key. The raw error message is shown below, but "+
				"usually this is because you attempted to pipe a value into the "+
				"unseal command or you are executing outside of a terminal (tty). "+
				"You should run the unseal command from a terminal for maximum "+
				"security. If this is not an option, the unseal key can be provided "+
				"as the first argument to the unseal command. The raw error "+
				"was:\n\n%s", err)))
			return 1
		}
		unsealKey = strings.TrimSpace(value)
	}

	status, err := client.Sys().UnsealNamespace(
		&api.UnsealNamespaceRequest{
			Name: namespacePath,
			Key:  unsealKey,
		},
	)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error unsealing: %s", err))
		return 2
	}

	return OutputData(c.UI, SealStatusOutput{SealStatusResponse: api.SealStatusResponse{
		Type:        status.Type,
		Initialized: status.Initialized,
		Sealed:      status.Sealed,
		T:           status.T,
		N:           status.N,
		Progress:    status.Progress,
		Nonce:       status.Nonce,
	}})
}
