package command

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

const (
	subkeysAPIPath           = "subkeys"
	subkeysResponseDataField = "subkeys"
)

var (
	_ cli.Command             = (*KVSubkeysCommand)(nil)
	_ cli.CommandAutocomplete = (*KVSubkeysCommand)(nil)
)

type KVSubkeysCommand struct {
	*BaseCommand

	flagMount   string
	flagVersion int
	flagDepth   int
}

func (c *KVSubkeysCommand) Synopsis() string {
	return "Retrieves the subkeys of a KV without their values"
}

func (c *KVSubkeysCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultFiles()
}

func (c *KVSubkeysCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Common Options")

	f.StringVar(&StringVar{
		Name:    "mount",
		Target:  &c.flagMount,
		Default: "",
		Usage: `Specifies the path where the KV backend is mounted. If specified,
		the next argument will be interpreted as the secret path. If this flag is 
		not specified, the next argument will be interpreted as the combined mount 
		path and secret path, with /subkeys/ automatically inserted between them.`,
	})
	f.IntVar(&IntVar{
		Name:    "version",
		Target:  &c.flagVersion,
		Default: 0,
		Usage: `Specifies the version of the secret for which the subkeys are returned.
		By default, the current version is used.`,
	})
	f.IntVar(&IntVar{
		Name:    "depth",
		Target:  &c.flagDepth,
		Default: 0,
		Usage: `Specifies the maximum nesting depth of the returned subkeys.
		By default, no depth limit is applied.`,
	})

	return set
}

func (c *KVSubkeysCommand) Help() string {
	helpText := `
Usage: bao kv subkeys [options] PATH

  Retrieves the key structure of a secret from OpenBao's key-value store 
  without its values. If no secret exists at the given path, an error is 
  returned. Requires KV Version 2.

      $ bao kv subkeys -mount=secret foo

  The deprecated path-like syntax can also be used, but this should be avoided 
  for KV v2, as the fact that it is not actually the full API path to 
  the secret (secret/subkeys/foo) can cause confusion: 

      $ bao kv subkeys secret/foo

  To retrieve the subkeys for a specific version, specify the “-version” flag:

      $ bao kv subkeys -mount=secret -version=2 foo

  To limit the nesting depth, specify the “-depth” flag:

      $ bao kv subkeys -mount=secret -depth=1 foo

  By default, the latest version is used, and there is no depth limit.
` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *KVSubkeysCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *KVSubkeysCommand) Run(args []string) int {
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

	partialPath := sanitizePath(args[0])
	if partialPath == "" {
		c.UI.Error("Secret path must not be empty")
		return 1
	}

	if c.flagVersion < 0 {
		c.UI.Error("Version must be greater than or equal to zero")
		return 1
	}

	if c.flagDepth < 0 {
		c.UI.Error("Depth must be greater than or equal to zero")
		return 1
	}

	mountFlagSyntax := c.flagMount != ""

	lookupPath := partialPath
	if mountFlagSyntax {
		lookupPath = sanitizePath(c.flagMount)
	}

	mountPath, v2, err := isKVv2(lookupPath, client)
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	if !v2 {
		c.UI.Error("Subkeys require KV Version 2")
		return 1
	}

	if mountFlagSyntax {
		partialPath = path.Join(mountPath, partialPath)
	}

	fullPath := addPrefixToKVPath(partialPath, mountPath, subkeysAPIPath, false)

	params := make(map[string]string)
	if c.flagVersion > 0 {
		params["version"] = strconv.Itoa(c.flagVersion)
	}
	if c.flagDepth > 0 {
		params["depth"] = strconv.Itoa(c.flagDepth)
	}

	secret, err := kvReadRequest(client, fullPath, params)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading %s: %s", fullPath, err))
		return 2
	}
	if secret == nil {
		c.UI.Error(fmt.Sprintf("No value found at %s", fullPath))
		return 2
	}

	if secret.WrapInfo != nil {
		return OutputSecret(c.UI, secret)
	}

	printWarnings(c.UI, secret)

	subkeys, ok := secret.Data[subkeysResponseDataField]
	if !ok || subkeys == nil {
		c.UI.Error(fmt.Sprintf("No subkeys found at %s", fullPath))
		return 2
	}

	return OutputData(c.UI, subkeys)
}
