// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/roottoken"
	"github.com/openbao/openbao/vault"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceGenerateRootCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceGenerateRootCommand)(nil)
)

type NamespaceGenerateRootCommand struct {
	*BaseCommand

	flagInit        bool
	flagCancel      bool
	flagStatus      bool
	flagDecode      string
	flagOTP         string
	flagPGPKey      string
	flagNonce       string
	flagGenerateOTP bool

	testStdin io.Reader // for tests
}

func (c *NamespaceGenerateRootCommand) Synopsis() string {
	return "Generate a new root token for a sealable namespace"
}

func (c *NamespaceGenerateRootCommand) Help() string {
	helpText := `
Usage: bao namespace generate-root [options] PATH [KEY]

  Generates a new root token by combining a quorum of share holders. One of
  the following must be provided to start the root token generation:

    - A base64-encoded one-time-password (OTP) provided via the "-otp" flag.
      Use the "-generate-otp" flag to generate a usable value. The resulting
      token is XORed with this value when it is returned. Use the "-decode"
      flag to output the final value.

    - A file containing a PGP key or a keybase username in the "-pgp-key"
      flag. The resulting token is encrypted with this public key.

  An unseal key may be provided directly on the command line as an argument to
  the command. If key is specified as "-", the command will read from stdin. If
  a TTY is available, the command will prompt for text.

  Generate an OTP code for the final token:

      $ bao namespace generate-root -generate-otp

  Start a root token generation:

      $ bao namespace generate-root -init -otp="..." PATH
      $ bao namespace generate-root -init -pgp-key="..." PATH

  Enter an unseal key to progress root token generation:

      $ bao namespace generate-root -otp="..." PATH

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *NamespaceGenerateRootCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:    "init",
		Target:  &c.flagInit,
		Default: false,
		Usage: "Start a root token generation for a given namespace. This can only be done if " +
			"there is currently not another one in progress for the namespace.",
	})

	f.BoolVar(&BoolVar{
		Name:    "cancel",
		Target:  &c.flagCancel,
		Default: false,
		Usage: "Reset the root token generation progress for a given namespace. This will discard any " +
			"submitted unseal keys or configuration.",
	})

	f.BoolVar(&BoolVar{
		Name:       "status",
		Target:     &c.flagStatus,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage: "Print the status of the current attempt for the given namespace without providing an " +
			"unseal key.",
	})

	f.StringVar(&StringVar{
		Name:       "decode",
		Target:     &c.flagDecode,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "The value to decode; setting this triggers a decode operation. " +
			" If the value is \"-\" then read the encoded token from stdin.",
	})

	f.BoolVar(&BoolVar{
		Name:       "generate-otp",
		Target:     &c.flagGenerateOTP,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage: "Generate and print a high-entropy one-time-password (OTP) " +
			"suitable for use with the \"-init\" flag.",
	})

	f.StringVar(&StringVar{
		Name:       "otp",
		Target:     &c.flagOTP,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "OTP code to use with \"-decode\" or \"-init\".",
	})

	f.VarFlag(&VarFlag{
		Name:       "pgp-key",
		Value:      (*pgpkeys.PubKeyFileFlag)(&c.flagPGPKey),
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Path to a file on disk containing a binary or base64-encoded " +
			"public PGP key. This can also be specified as a Keybase username " +
			"using the format \"keybase:<username>\". When supplied, the generated " +
			"root token will be encrypted and base64-encoded with the given public " +
			"key.",
	})

	f.StringVar(&StringVar{
		Name:       "nonce",
		Target:     &c.flagNonce,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Nonce value provided at initialization. The same nonce value " +
			"must be provided with each unseal key.",
	})

	return set
}

func (c *NamespaceGenerateRootCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *NamespaceGenerateRootCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceGenerateRootCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) < 1 {
		c.UI.Error("Not enough arguments (expected 1-2, got 0)")
		return 1
	}
	if len(args) > 2 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1-2, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	namespacePath := strings.TrimSpace(args[0])
	switch {
	case c.flagGenerateOTP:
		otp, code := c.generateOTP(client, namespacePath)
		if code == 0 {
			switch Format(c.UI) {
			case "", "table":
				return PrintRaw(c.UI, otp)
			default:
				status := map[string]interface{}{
					"otp":        otp,
					"otp_length": len(otp),
				}
				return OutputData(c.UI, status)
			}
		}
		return code
	case c.flagDecode != "":
		return c.decode(client, c.flagDecode, c.flagOTP, namespacePath)
	case c.flagCancel:
		return c.cancel(client, namespacePath)
	case c.flagInit:
		return c.init(client, c.flagOTP, c.flagPGPKey, namespacePath)
	case c.flagStatus:
		return c.status(client, namespacePath)
	default:
		// If there are no other flags, prompt for an unseal key.
		key := ""
		if len(args) > 1 {
			key = strings.TrimSpace(args[1])
		}
		return c.provide(client, key, namespacePath)
	}
}

func (c *NamespaceGenerateRootCommand) generateOTP(client *api.Client, namespacePath string) (string, int) {
	status, err := client.Sys().NamespaceGenerateRootStatus(namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting root generation status: %s", err))
		return "", 2
	}

	otpLength := status.OTPLength
	if otpLength == 0 {
		otpLength = vault.NSTokenLength + vault.TokenPrefixLength
	}
	otp, err := base62.Random(otpLength)
	var retCode int
	if err != nil {
		retCode = 2
		c.UI.Error(err.Error())
	} else {
		retCode = 0
	}
	return otp, retCode
}

func (c *NamespaceGenerateRootCommand) decode(client *api.Client, encoded, otp, namespacePath string) int {
	if encoded == "" {
		c.UI.Error("Missing encoded value: use -decode=<string> to supply it")
		return 1
	}
	if otp == "" {
		c.UI.Error("Missing otp: use -otp to supply it")
		return 1
	}

	if encoded == "-" {
		// Pull our fake stdin if needed
		stdin := (io.Reader)(os.Stdin)
		if c.testStdin != nil {
			stdin = c.testStdin
		}
		if c.flagNonInteractive {
			stdin = bytes.NewReader(nil)
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, stdin); err != nil {
			c.UI.Error(fmt.Sprintf("Failed to read from stdin: %s", err))
			return 1
		}

		encoded = buf.String()

		if encoded == "" {
			c.UI.Error("Missing encoded value. When using -decode=\"-\" value must be passed via stdin.")
			return 1
		}
	}

	status, err := client.Sys().NamespaceGenerateRootStatus(namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting root generation status: %s", err))
		return 2
	}

	token, err := roottoken.DecodeToken(encoded, otp, status.OTPLength)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error decoding root token: %s", err))
		return 1
	}

	switch Format(c.UI) {
	case "", "table":
		return PrintRaw(c.UI, token)
	default:
		tokenJSON := map[string]interface{}{
			"token": token,
		}
		return OutputData(c.UI, tokenJSON)
	}
}

// init is used to start the generation process
func (c *NamespaceGenerateRootCommand) init(client *api.Client, otp, pgpKey, namespacePath string) int {
	// Validate incoming fields. Either OTP OR PGP keys must be supplied.
	if otp != "" && pgpKey != "" {
		c.UI.Error("Error initializing: cannot specify both -otp and -pgp-key")
		return 1
	}

	// Start the root generation
	status, err := client.Sys().NamespaceGenerateRootInit(otp, pgpKey, namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing root generation: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

// provide prompts the user for the seal key and posts it to the update root
// endpoint. If this is the last unseal, this function outputs it.
func (c *NamespaceGenerateRootCommand) provide(client *api.Client, key, namespacePath string) int {
	status, err := client.Sys().NamespaceGenerateRootStatus(namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting root generation status: %s", err))
		return 2
	}

	// Verify a root token generation is in progress. If there is not one in
	// progress, return an error instructing the user to start one.
	if !status.Started {
		c.UI.Error(wrapAtLength(
			"No root generation is in progress for this namespace. Start a root generation by " +
				"running \"bao namespace generate-root -init PATH\"."))
		c.UI.Warn(wrapAtLength(fmt.Sprintf(
			"If starting root generation using the OTP method and generating "+
				"your own OTP, the length of the OTP string needs to be %d "+
				"characters in length.", status.OTPLength)))
		return 1
	}

	var nonce string

	switch key {
	case "-": // Read from stdin
		nonce = status.Nonce

		// Pull our fake stdin if needed
		stdin := (io.Reader)(os.Stdin)
		if c.testStdin != nil {
			stdin = c.testStdin
		}
		if c.flagNonInteractive {
			stdin = bytes.NewReader(nil)
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, stdin); err != nil {
			c.UI.Error(fmt.Sprintf("Failed to read from stdin: %s", err))
			return 1
		}

		key = buf.String()
	case "": // Prompt using the tty
		// Nonce value is not required if we are prompting via the terminal
		nonce = status.Nonce

		if c.flagNonInteractive {
			c.UI.Error(wrapAtLength("Refusing to read from stdin with -non-interactive specified; specify nonce via the -nonce flag"))
			return 1
		}

		c.UI.Output(fmt.Sprintf("Operation nonce: %s\n", nonce))
		c.UI.Output("Unseal Key (will be hidden): ")

		key, err = password.Read(os.Stdin)
		c.UI.Output("\n")

		if err != nil {
			if err == password.ErrInterrupted {
				c.UI.Error("user canceled")
				return 1
			}

			c.UI.Error(wrapAtLength(fmt.Sprintf("An error occurred attempting to "+
				"ask for the unseal key. The raw error message is shown below, but "+
				"usually this is because you attempted to pipe a value into the "+
				"command or you are executing outside of a terminal (tty). If you "+
				"want to pipe the value, pass \"-\" as the argument to read from "+
				"stdin. The raw error was: %s", err)))
			return 1
		}
	default: // Supplied directly as an arg
		nonce = status.Nonce
	}

	// Trim any whitespace from the key, especially since we might have prompted
	// the user for it.
	key = strings.TrimSpace(key)

	// Verify we have a nonce value
	if nonce == "" {
		c.UI.Error("Missing nonce value: specify it via the -nonce flag")
		return 1
	}

	// Provide the key, this may potentially complete the update
	status, err = client.Sys().NamespaceGenerateRootUpdate(key, nonce, namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error posting unseal key: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

func (c *NamespaceGenerateRootCommand) cancel(client *api.Client, namespacePath string) int {
	err := client.Sys().NamespaceGenerateRootCancel(namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error canceling root token generation: %s", err))
		return 2
	}
	c.UI.Output(fmt.Sprintf("Cancelled any ongoing root token generation operations for namespace: %q", namespacePath))
	return 0
}

func (c *NamespaceGenerateRootCommand) status(client *api.Client, namespacePath string) int {
	status, err := client.Sys().NamespaceGenerateRootStatus(namespacePath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting root generation status: %s", err))
		return 2
	}
	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

// printStatus dumps the status to output
func (c *NamespaceGenerateRootCommand) printStatus(status *api.GenerateRootStatusResponse) int {
	out := []string{}
	out = append(out, fmt.Sprintf("Nonce | %s", status.Nonce))
	out = append(out, fmt.Sprintf("Started | %t", status.Started))
	out = append(out, fmt.Sprintf("Progress | %d/%d", status.Progress, status.Required))
	out = append(out, fmt.Sprintf("Complete | %t", status.Complete))
	if status.PGPFingerprint != "" {
		out = append(out, fmt.Sprintf("PGP Fingerprint | %s", status.PGPFingerprint))
	}
	if status.EncodedToken != "" {
		out = append(out, fmt.Sprintf("Encoded Token | %s", status.EncodedToken))
	}
	if status.OTP != "" {
		c.UI.Warn(wrapAtLength("A One-Time-Password has been generated for you and is shown in the OTP field. You will need this value to decode the resulting root token, so keep it safe."))
		out = append(out, fmt.Sprintf("OTP | %s", status.OTP))
	}
	if status.OTPLength != 0 {
		out = append(out, fmt.Sprintf("OTP Length | %d", status.OTPLength))
	}

	output := columnOutput(out, nil)
	c.UI.Output(output)
	return 0
}
