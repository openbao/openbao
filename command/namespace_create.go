// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/vault"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceCreateCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceCreateCommand)(nil)
)

type NamespaceCreateCommand struct {
	*BaseCommand

	flagCustomMetadata  map[string]string
	flagSealsConfigPath string
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
		Usage: `Specifies arbitrary key=value metadata meant to describe a namespace.
		Can be specified multiple times to add multiple pieces of metadata.`,
	})

	f.StringVar(&StringVar{
		Name:       "seals",
		Target:     &c.flagSealsConfigPath,
		Completion: complete.PredictFiles("*.json"),
		Usage: `Path to a JSON file with a list of namespace seal configurations. 
		Must be a JSON array with at least one valid configuration.`,
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

	sealConfigs, err := c.parseSeals()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing seal configs: %s", err))
		return 2
	}

	data := map[string]interface{}{
		"custom_metadata": c.flagCustomMetadata,
		"seals":           sealConfigs,
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

	if len(sealConfigs) > 0 {
		// TODO(wslabosz): handle output for multiple seals
		keySharesMap, ok := secret.Data["key_shares"].(map[string]interface{})
		if ok {
			defaultKeyShares := keySharesMap["default"].([]interface{})
			for i, key := range defaultKeyShares {
				c.UI.Output(fmt.Sprintf("Unseal Key %d: %s", i+1, key))
			}
		}

		// for now the assumption is that there's just one config
		secretShares := sealConfigs[0].SecretShares
		secretThreshold := sealConfigs[0].SecretThreshold

		c.UI.Output("")
		c.UI.Output(wrapAtLength(fmt.Sprintf(
			"Namespace initialized with %d key shares and a key threshold of %d. Please "+
				"securely distribute the key shares printed above. When namespace is "+
				"re-sealed you must supply at least %d of "+
				"these keys to unseal it before it can start serving requests.",
			secretShares,
			secretThreshold,
			secretThreshold)))
		c.UI.Output("")
	}

	return OutputSecret(c.UI, secret)
}

func (c *NamespaceCreateCommand) parseSeals() ([]*vault.SealConfig, error) {
	path := c.flagSealsConfigPath
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var sealConfigs []*vault.SealConfig
	if err := json.Unmarshal(data, &sealConfigs); err != nil {
		return nil, err
	}

	return sealConfigs, nil
}
