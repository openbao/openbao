// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/roottoken"
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
	flagNonce       string
	flagStatus      bool
	flagDecode      string
	flagOTP         string
	flagGenerateOTP bool
}

func (c *NamespaceGenerateRootCommand) Synopsis() string {
	return "Generate a new root token for a sealed namespace"
}

func (c *NamespaceGenerateRootCommand) Help() string {
	helpText := `
Usage: bao namespace generate-root [options] <NamespacePath>

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

      $ bao namespace generate-root -init -otp="..." <NamespacePath>
      $ bao namespace generate-root -init -pgp-key="..." <NamespacePath>

  Enter an unseal key to progress root token generation:

      $ bao namespace generate-root -otp="..." <NamespacePath>

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
			"there is not currently one in progress for the namespace.",
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
		Name:       "nonce",
		Target:     &c.flagNonce,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Nonce value provided at initialization. The same nonce value " +
			"must be provided with each unseal key.",
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

	f.StringVar(&StringVar{
		Name:       "otp",
		Target:     &c.flagOTP,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "OTP code to use with \"-decode\" or \"-init\".",
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
	if len(args) == 0 && !c.flagGenerateOTP {
		c.UI.Error("Missing mandatory parameter: namespace")
		return 1
	}
	if len(args) > 2 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0-2, got %d)", len(args)))
		return 1
	}

	namespacePath := strings.TrimSpace(args[0])

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

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
	case c.flagInit:
		return c.init(client, "", "", namespacePath)
	case c.flagDecode != "":
		return c.decode(client, c.flagDecode, c.flagOTP, namespacePath)
	case c.flagCancel:
		return c.cancel(client, namespacePath)
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

// init is used to start the generation process
func (c *NamespaceGenerateRootCommand) init(client *api.Client, otp, pgpKey string, namespacePath string) int {
	// Validate incoming fields. Either OTP OR PGP keys must be supplied.
	if otp != "" && pgpKey != "" {
		c.UI.Error("Error initializing: cannot specify both -otp and -pgp-key")
		return 1
	}

	// Start the root generation
	secret, err := client.Logical().Write("sys/namespaces/"+namespacePath+"/generate-root/attempt", map[string]interface{}{})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing root generation: %s", err))
		return 2
	}

	status, err := c.extractResponse(secret.Data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while extracting root generation status: %s", err))
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
func (c *NamespaceGenerateRootCommand) provide(client *api.Client, key string, namespacePath string) int {
	secret, err := client.Logical().Read("sys/namespaces/" + namespacePath + "/generate-root/attempt")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while getting root generation status: %s", err))
		return 2
	}

	status, err := c.extractResponse(secret.Data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while extracting root generation status: %s", err))
		return 2
	}

	// Verify a root token generation is in progress. If there is not one in
	// progress, return an error instructing the user to start one.
	if !status.Started {
		c.UI.Error(wrapAtLength(
			"No root generation is in progress for this namespace. Start a root generation by " +
				"running \"bao namespace generate-root -init <NamespacePath>\"."))
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

		w := getWriterFromUI(c.UI)
		fmt.Fprintf(w, "Operation nonce: %s\n", nonce)
		fmt.Fprintf(w, "Unseal Key (will be hidden): ")
		key, err = password.Read(os.Stdin)
		fmt.Fprintf(w, "\n")
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

	// Trim any whitespace from they key, especially since we might have prompted
	// the user for it.
	key = strings.TrimSpace(key)

	// Verify we have a nonce value
	if nonce == "" {
		c.UI.Error("Missing nonce value: specify it via the -nonce flag")
		return 1
	}

	// Provide the key, this may potentially complete the update
	data := map[string]interface{}{"key": key, "nonce": nonce}

	secret, err = client.Logical().Write("sys/namespaces/"+namespacePath+"/generate-root/update", data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error posting unseal key: %s", err))
		return 2
	}
	status, err = c.extractResponse(secret.Data)
	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

func (c *NamespaceGenerateRootCommand) cancel(client *api.Client, namespacePath string) int {
	_, err := client.Logical().Delete("sys/namespaces/" + namespacePath + "/generate-root/attempt")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error canceling root token generation: %s", err))
		return 2
	}
	c.UI.Output(fmt.Sprintf("Cancelled any ongoing root token generation operations for namespace: %q", namespacePath))
	return 0
}

func (c *NamespaceGenerateRootCommand) decode(client *api.Client, encoded, otp string, namespacePath string) int {
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

	secret, err := client.Logical().Read("sys/namespaces/" + namespacePath + "/generate-root/attempt")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while getting root generation status: %s", err))
		return 2
	}

	status, err := c.extractResponse(secret.Data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while extracting root generation status: %s", err))
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

func (c *NamespaceGenerateRootCommand) status(client *api.Client, namespacePath string) int {
	secret, err := client.Logical().Read("sys/namespaces/" + namespacePath + "/generate-root/attempt")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing root generation: %s", err))
		return 2
	}

	status, err := c.extractResponse(secret.Data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while extracting root generation status: %s", err))
		return 2
	}
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

func (c *NamespaceGenerateRootCommand) generateOTP(client *api.Client, namespacePath string) (string, int) {
	secret, err := client.Logical().Read("sys/namespaces/" + namespacePath + "/generate-root/attempt")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing root generation: %s", err))
		return "", 2
	}

	status, err := c.extractResponse(secret.Data)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error while extracting root generation status: %s", err))
		return "", 2
	}

	otp, err := roottoken.GenerateOTP(status.OTPLength)
	var retCode int
	if err != nil {
		retCode = 2
		c.UI.Error(err.Error())
	} else {
		retCode = 0
	}
	return otp, retCode
}

// printStatus dumps the status to output
func (c *NamespaceGenerateRootCommand) printStatus(status *NamespaceGenerateRootResponse) int {
	out := []string{}
	out = append(out, fmt.Sprintf("Nonce | %s", status.Nonce))
	out = append(out, fmt.Sprintf("Started | %t", status.Started))
	out = append(out, fmt.Sprintf("Progress | %d/%d", status.Progress, status.Required))
	out = append(out, fmt.Sprintf("Complete | %t", status.Complete))
	if status.PGPFingerprint != "" {
		out = append(out, fmt.Sprintf("PGP Fingerprint | %s", status.PGPFingerprint))
	}
	switch {
	case status.EncodedToken != "":
		out = append(out, fmt.Sprintf("Encoded Token | %s", status.EncodedToken))
	case status.EncodedRootToken != "":
		out = append(out, fmt.Sprintf("Encoded Root Token | %s", status.EncodedRootToken))
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

func (c *NamespaceGenerateRootCommand) extractResponse(data map[string]interface{}) (*NamespaceGenerateRootResponse, error) {
	jsonStatus, err := json.Marshal(data)
	if err != nil {
		return &NamespaceGenerateRootResponse{}, nil
	}
	status := NamespaceGenerateRootResponse{}
	json.Unmarshal(jsonStatus, &status)

	return &status, nil
}

type NamespaceGenerateRootResponse struct {
	Nonce            string `json:"nonce"`
	Started          bool   `json:"started"`
	Progress         int    `json:"progress"`
	Required         int    `json:"required"`
	Complete         bool   `json:"complete"`
	EncodedToken     string `json:"encoded_token"`
	EncodedRootToken string `json:"encoded_root_token"`
	PGPFingerprint   string `json:"pgp_fingerprint"`
	OTP              string `json:"otp"`
	OTPLength        int    `json:"otp_length"`
}
