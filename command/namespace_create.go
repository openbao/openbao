// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/helper/pgpkeys"
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

	sealConfig, err := c.readSealConfig()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while parsing seal configs: %s", err))
		return 2
	}

	data := map[string]interface{}{
		"custom_metadata": c.flagCustomMetadata,
	}

	if sealConfig != nil {
		data["seal"] = string(sealConfig)
	}

	if c.flagKeyShares != 0 || c.flagKeyThreshold != 0 {
		// if either -key-shares or -key-threshold is given, assume we create a
		// shamir-sealed namespace; unless an explicit seal config was given
		if _, ok := data["seal"]; !ok {
			data["seal"] = fmt.Sprintf(`seal "shamir" {
    shares = %d
    threshold = %d
}`, c.flagKeyShares, c.flagKeyThreshold)
		}
	}

	if len(c.flagPGPKeys) > 0 {
		data["pgp_keys"] = c.flagPGPKeys
	}

	secret, err := client.Logical().Write("sys/namespaces/"+namespacePath, data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating namespace: %s", err))
		return 2
	}

	// Handle single field output
	if c.flagField != "" {
		return PrintRawField(c.UI, secret, c.flagField)
	}

	return OutputSecret(c.UI, secret)
}

func (c *NamespaceCreateCommand) readSealConfig() ([]byte, error) {
	path := c.flagSealConfigPath
	if path == "" {
		return nil, nil
	}

	return os.ReadFile(path)
}
