// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/structtomap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceCreateCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceCreateCommand)(nil)
)

type NamespaceCreateCommand struct {
	*BaseCommand

	flagCustomMetadata map[string]string
	flagSealConfigPath string
	flagKeyShares      int
	flagKeyThreshold   int
	flagPGPKeys        []string
}

func (c *NamespaceCreateCommand) Synopsis() string {
	return "Create a new namespace"
}

func (c *NamespaceCreateCommand) Help() string {
	helpText := `
Usage: bao namespace create [options] PATH

  Create a child namespace. The namespace created will be relative to the
  namespace provided in either the BAO_NAMESPACE environment variable or
  -namespace CLI flag.

  Create a child namespace (e.g. ns1/):

      $ bao namespace create ns1

  Create a child namespace from a parent namespace (e.g. ns1/ns2/):

      $ bao namespace create -namespace=ns1 ns2

  Create a sealable namespace with Shamir seal:

      $ bao namespace create -key-shares=5 -key-threshold=3 ns1

  Create a sealable namespace from a HCL seal config file:

      $ bao namespace create -seal=seal.hcl ns1

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceCreateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	f.StringMapVar(&StringMapVar{
		Name:    "custom-metadata",
		Target:  &c.flagCustomMetadata,
		Default: map[string]string{},
		Usage: "Specifies arbitrary key=value metadata meant to describe a namespace." +
			"This can be specified multiple times to add multiple pieces of metadata.",
	})

	f = set.NewFlagSet("Seal Options")
	f.StringVar(&StringVar{
		Name:       "seal",
		Target:     &c.flagSealConfigPath,
		Completion: complete.PredictFilesSet([]string{"*.hcl", "*.json"}),
		Usage:      "Path to a HCL file with exactly one seal stanza.",
	})

	f.IntVar(&IntVar{
		Name:       "key-shares",
		Aliases:    []string{"n"},
		Target:     &c.flagKeyShares,
		Completion: complete.PredictAnything,
		Usage: "Number of key shares to split the generated root key into. " +
			"This is the number of \"unseal keys\" to generate.",
	})

	f.IntVar(&IntVar{
		Name:       "key-threshold",
		Aliases:    []string{"t"},
		Target:     &c.flagKeyThreshold,
		Completion: complete.PredictAnything,
		Usage: "Number of key shares required to reconstruct the root key. " +
			"This must be less than or equal to -key-shares.",
	})

	f.VarFlag(&VarFlag{
		Name:       "pgp-keys",
		Value:      (*pgpkeys.PubKeyFilesFlag)(&c.flagPGPKeys),
		Completion: complete.PredictAnything,
		Usage: "Comma-separated list of paths to files on disk containing " +
			"public PGP keys OR a comma-separated list of Keybase usernames using " +
			"the format \"keybase:<username>\". When supplied, the generated " +
			"unseal keys will be encrypted and base64-encoded in the order " +
			"specified in this list. The number of entries must match -key-shares.",
	})

	return set
}

func (c *NamespaceCreateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *NamespaceCreateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceCreateCommand) Run(args []string) int {
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

	input := &api.CreateNamespaceInput{
		CustomMetadata: c.flagCustomMetadata,
		PGPKeys:        c.flagPGPKeys,
	}

	if c.flagSealConfigPath != "" {
		hcl, err := os.ReadFile(c.flagSealConfigPath)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error reading seal config file: %s", err))
			return 2
		}
		input.Seal = string(hcl)
	} else if c.flagKeyShares != 0 || c.flagKeyThreshold != 0 {
		input.Seal = fmt.Sprintf("seal \"shamir\" {\n    shares = %d\n    threshold = %d\n}",
			c.flagKeyShares, c.flagKeyThreshold)
	}

	resp, err := client.Sys().CreateNamespace(namespacePath, input)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating namespace: %s", err))
		return 2
	}

	if resp != nil && len(resp.KeyShares) > 0 {
		for i, key := range resp.KeyShares {
			c.UI.Output(fmt.Sprintf("Unseal Key %d: %s", i+1, key))
		}
		c.UI.Output("")
		c.UI.Output(wrapAtLength(fmt.Sprintf(
			"Namespace initialized with %d key shares and a key threshold of %d. Please "+
				"securely distribute the key shares printed above. When the namespace is "+
				"re-sealed, you must supply at least %d of these keys to unseal it.",
			len(resp.KeyShares),
			resp.KeyThreshold,
			resp.KeyThreshold,
		)))
		c.UI.Output("")
	}

	out := structtomap.Map(resp)

	if c.flagField != "" {
		return PrintRawField(c.UI, out, c.flagField)
	}

	return OutputData(c.UI, out)
}
