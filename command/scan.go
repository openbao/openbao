// Copyright (c) HashiCorp, Inc.
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
	_ cli.Command             = (*ScanCommand)(nil)
	_ cli.CommandAutocomplete = (*ScanCommand)(nil)
)

type ScanCommand struct {
	*BaseCommand

	flagAfter string
	flagLimit int
}

func (c *ScanCommand) Synopsis() string {
	return "Scan (recursively list) data or secrets"
}

func (c *ScanCommand) Help() string {
	helpText := `

Usage: bao scan [options] PATH

  Scans data from Vault at the given path. This can be used to scan keys in a
  given secret engine. Scanning amounts to a recursive listing on all entries.

  Scan values under the "my-app" folder of the generic secret engine:

      $ bao scan secret/my-app/

  Some paths support paginated scanning. Use the -after and -limit flags to
  control the return of data:

      $ bao scan -after=last-serial -limit=50 pki/certs

  Some paths may support returning additional information about items;
  use the -detailed flag to see this info:

      $ bao scan -detailed secret/detailed-metadata/foo

  For a full list of examples and paths, please see the documentation that
  corresponds to the secret engine in use. Not all engines support scanning.

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *ScanCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat | FlagSetOutputDetailed)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "after",
		Target:  &c.flagAfter,
		Default: "",
		Usage: "Last seen key on applicable endpoints; the next key" +
			"alphabetically will be the first returned.",
	})

	f.IntVar(&IntVar{
		Name:    "limit",
		Target:  &c.flagLimit,
		Default: -1,
		Usage:   "Limits the number of scan responses on applicable endpoints.",
	})

	return set
}

func (c *ScanCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultFolders()
}

func (c *ScanCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ScanCommand) Run(args []string) int {
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

	path := sanitizePath(args[0])

	// Only dispatch a ScanPage operation if flags were given; this avoids
	// a warning from the server about unrecognized parameters if the scan
	// endpoint doesn't understand pagination.
	var secret *api.Secret
	if c.flagAfter == "" && c.flagLimit <= 0 {
		secret, err = client.Logical().Scan(path)
	} else {
		secret, err = client.Logical().ScanPage(path, c.flagAfter, c.flagLimit)
	}
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error scanning %s: %s", path, err))
		return 2
	}

	// If the secret is wrapped, return the wrapped response.
	if secret != nil && secret.WrapInfo != nil && secret.WrapInfo.TTL != 0 {
		return OutputSecret(c.UI, secret)
	}

	_, ok := extractListData(secret)
	if Format(c.UI) != "table" {
		if secret == nil || secret.Data == nil || !ok {
			OutputData(c.UI, map[string]interface{}{})
			return 2
		}
	}

	if secret == nil {
		c.UI.Error(fmt.Sprintf("No value found at %s", path))
		return 2
	}
	if secret.Data == nil {
		// If secret wasn't nil, we have warnings, so output them anyways. We
		// may also have non-keys info.
		return OutputSecret(c.UI, secret)
	}

	if !ok {
		c.UI.Error(fmt.Sprintf("No entries found at %s", path))
		return 2
	}

	return OutputList(c.UI, secret)
}
