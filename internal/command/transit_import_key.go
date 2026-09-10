// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/openbao/openbao/api/v2"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_       cli.Command             = (*TransitImportCommand)(nil)
	_       cli.CommandAutocomplete = (*TransitImportCommand)(nil)
	keyPath                         = regexp.MustCompile("^(.*)/keys/([^/]*)$")
)

type TransitImportCommand struct {
	*BaseCommand
	keyFormat string
}

func (c *TransitImportCommand) Synopsis() string {
	return "Import a key into the Transit secrets engines."
}

func (c *TransitImportCommand) Help() string {
	helpText := `
Usage: bao transit import [flags] PATH KEY [options...]

  Using the Transit key wrapping system, imports key material from
  the base64 encoded KEY (either directly on the CLI or via @path notation),
  into a new key whose API path is PATH. Use -key-format=raw or -key-format=pem
  with @path to read binary key material or an unencrypted private-key PEM file.
  To import a new version into an existing key, use import-version. The remaining
  options after KEY (key=value style) are passed on to the Transit create key
  endpoint. If your
  system or device natively supports the RSA AES key wrap mechanism (such as
  the PKCS#11 mechanism CKM_RSA_AES_KEY_WRAP), you should use it directly
  rather than this command.

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *TransitImportCommand) Flags() *FlagSets {
	return transitImportFlags(c.BaseCommand, &c.keyFormat)
}

func transitImportFlags(c *BaseCommand, keyFormat *string) *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Import Options")
	f.StringVar(&StringVar{
		Name:       "key-format",
		Target:     keyFormat,
		Default:    "base64",
		Completion: complete.PredictSet("base64", "raw", "pem"),
		Usage: "Format of the source key: base64, raw, or pem. Raw and PEM require " +
			"@path notation. Raw reads binary key material unchanged; PEM converts " +
			"an unencrypted PKCS#8, PKCS#1 RSA, or SEC1 EC private key to PKCS#8 DER.",
	})
	return set
}

func (c *TransitImportCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *TransitImportCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TransitImportCommand) Run(args []string) int {
	return ImportKey(c.BaseCommand, "import", transitImportKeyPath, c.Flags(), &c.keyFormat, args)
}

func transitImportKeyPath(s string, operation string) (path string, apiPath string, err error) {
	parts := keyPath.FindStringSubmatch(s)
	if len(parts) != 3 {
		//nolint:staticcheck // colon is used for path placeholders
		return "", "", errors.New("expected transit path and key name in the form :path:/keys/:name:")
	}
	path = parts[1]
	keyName := parts[2]
	apiPath = path + "/keys/" + keyName + "/" + operation

	return path, apiPath, nil
}

type ImportKeyFunc func(s string, operation string) (path string, apiPath string, err error)

// error codes: 1: user error, 2: internal computation error, 3: remote api call error
func ImportKey(c *BaseCommand, operation string, pathFunc ImportKeyFunc, flags *FlagSets, keyFormat *string, args []string) int {
	// Parse and validate the arguments.
	if err := flags.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = flags.Args()
	if len(args) < 2 {
		c.UI.Error(fmt.Sprintf("Incorrect argument count (expected 2+, got %d). Wanted PATH to import into and KEY material.", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	ephemeralAESKey := make([]byte, 32)
	_, err = rand.Read(ephemeralAESKey)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failed to generate ephemeral key: %v", err))
	}
	path, apiPath, err := pathFunc(args[0], operation)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	key, err := readTransitImportKey(args[1], *keyFormat)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	// Fetch the wrapping key
	c.UI.Output("Retrieving wrapping key.")
	wrappingKey, err := fetchWrappingKey(c, client, path)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failed to fetch wrapping key: %v", err))
		return 3
	}
	c.UI.Output("Wrapping source key with ephemeral key.")
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failure building key wrapping key: %v", err))
		return 2
	}
	wrappedTargetKey, err := wrapKWP.Wrap(key)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failure wrapping source key: %v", err))
		return 2
	}
	c.UI.Output("Encrypting ephemeral key with wrapping key.")
	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		wrappingKey.(*rsa.PublicKey),
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failure encrypting wrapped key: %v", err))
		return 2
	}
	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	importCiphertext := base64.StdEncoding.EncodeToString(combinedCiphertext)

	// Parse all the key options
	var stdin io.Reader = os.Stdin
	if c.flagNonInteractive {
		stdin = bytes.NewReader(nil)
	}

	data, err := parseArgsData(stdin, args[2:])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to parse extra K=V data: %s", err))
		return 1
	}
	if data == nil {
		data = make(map[string]any, 1)
	}

	data["ciphertext"] = importCiphertext

	c.UI.Output("Submitting wrapped key.")
	// Finally, call import

	_, err = client.Logical().Write(apiPath, data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("failed to call import:%v", err))
		return 3
	} else {
		c.UI.Output("Success!")
		return 0
	}
}

func fetchWrappingKey(c *BaseCommand, client *api.Client, path string) (any, error) {
	resp, err := client.Logical().Read(path + "/wrapping_key")
	if err != nil {
		return nil, fmt.Errorf("error fetching wrapping key: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("no mount found at %s: %v", path, err)
	}
	key, ok := resp.Data["public_key"]
	if !ok {
		c.UI.Error("could not find wrapping key")
	}
	keyBlock, _ := pem.Decode([]byte(key.(string)))
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing wrapping key: %w", err)
	}
	return parsedKey, nil
}
