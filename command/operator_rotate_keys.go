// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*OperatorRotateKeysCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorRotateKeysCommand)(nil)
)

const (
	keyTypeRecovery = "Recovery"
	keyTypeUnseal   = "Unseal"
)

type OperatorRotateKeysCommand struct {
	*BaseCommand

	flagCancel       bool
	flagInit         bool
	flagKeyShares    int
	flagKeyThreshold int
	flagNonce        string
	flagPGPKeys      []string
	flagStatus       bool
	flagTarget       string
	flagVerify       bool

	// Backup options
	flagBackup         bool
	flagBackupDelete   bool
	flagBackupRetrieve bool

	testStdin io.Reader // for tests
}

func (c *OperatorRotateKeysCommand) Synopsis() string {
	return "Generates new unseal keys"
}

func (c *OperatorRotateKeysCommand) Help() string {
	helpText := `
Usage: bao operator rotate-keys [options] [KEY]

  Generates a new set of unseal keys. This can optionally change the total
  number of key shares or the required threshold of those key shares to
  reconstruct the root key. This operation is zero downtime, but it requires
  that the OpenBao instance is unsealed and a quorum of existing unseal keys
  are provided.

  An unseal key may be provided directly on the command line as an argument to
  the command. If key is specified as "-", the command will read from stdin. If
  a TTY is available, the command will prompt for text.

  If the flag -target=recovery is supplied, then this operation will require a
  quorum of recovery keys in order to generate a new set of recovery keys. 

  Initialize a rotation:

      $ bao operator rotate-keys \
          -init \
          -key-shares=15 \
          -key-threshold=9

  Rotate and encrypt the resulting unseal keys with PGP:

      $ bao operator rotate-keys \
          -init \
          -key-shares=3 \
          -key-threshold=2 \
          -pgp-keys="keybase:hashicorp,keybase:jefferai,keybase:sethvargo"

  Store encrypted PGP keys in OpenBao's core:

      $ bao operator rotate-keys \
          -init \
          -pgp-keys="..." \
          -backup

  Retrieve backed-up unseal keys:

      $ bao operator rotate-keys -backup-retrieve

  Delete backed-up unseal keys:

      $ bao operator rotate-keys -backup-delete

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorRotateKeysCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
	f := set.NewFlagSet("Common Options")

	f.BoolVar(&BoolVar{
		Name:    "init",
		Target:  &c.flagInit,
		Default: false,
		Usage: "Initialize the rotation. This can only be done if there's not " +
			"one in progress. Customize the new number of key shares and threshold " +
			"using the -key-shares and -key-threshold flags respectively.",
	})

	f.BoolVar(&BoolVar{
		Name:    "cancel",
		Target:  &c.flagCancel,
		Default: false,
		Usage: "Reset the rotation progress. This will discard any submitted " +
			"unseal keys, recovery keys, or configuration.",
	})

	f.BoolVar(&BoolVar{
		Name:    "status",
		Target:  &c.flagStatus,
		Default: false,
		Usage: "Print the status of the current attempt without providing an " +
			"unseal or recovery key.",
	})

	f.IntVar(&IntVar{
		Name:       "key-shares",
		Aliases:    []string{"n"},
		Target:     &c.flagKeyShares,
		Default:    5,
		Completion: complete.PredictAnything,
		Usage: "Number of key shares to split the generated root key into. " +
			"This is the number of \"unseal keys\" or \"recovery keys\" to generate.",
	})

	f.IntVar(&IntVar{
		Name:       "key-threshold",
		Aliases:    []string{"t"},
		Target:     &c.flagKeyThreshold,
		Default:    3,
		Completion: complete.PredictAnything,
		Usage: "Number of key shares required to reconstruct the root key. " +
			"This must be less than or equal to -key-shares.",
	})

	f.StringVar(&StringVar{
		Name:       "nonce",
		Target:     &c.flagNonce,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Nonce value provided at initialization. The same nonce value " +
			"must be provided with each unseal or recovery key.",
	})

	f.StringVar(&StringVar{
		Name:       "target",
		Target:     &c.flagTarget,
		Default:    "barrier",
		EnvVar:     "",
		Completion: complete.PredictSet("barrier", "recovery"),
		Usage: "Target for rotation. \"recovery\" only applies when HSM support " +
			"is enabled.",
	})

	f.BoolVar(&BoolVar{
		Name:    "verify",
		Target:  &c.flagVerify,
		Default: false,
		Usage: "Indicates that the action (-status, -cancel, or providing a key " +
			"share) will be affecting verification for the current rotation " +
			"attempt.",
	})

	f.VarFlag(&VarFlag{
		Name:       "pgp-keys",
		Value:      (*pgpkeys.PubKeyFilesFlag)(&c.flagPGPKeys),
		Completion: complete.PredictAnything,
		Usage: "Comma-separated list of paths to files on disk containing " +
			"public PGP keys OR a comma-separated list of Keybase usernames using " +
			"the format \"keybase:<username>\". When supplied, the generated " +
			"unseal or recovery keys will be encrypted and base64-encoded in the order " +
			"specified in this list.",
	})

	f = set.NewFlagSet("Backup Options")

	f.BoolVar(&BoolVar{
		Name:    "backup",
		Target:  &c.flagBackup,
		Default: false,
		Usage: "Store a backup of the current PGP encrypted unseal or recovery keys in " +
			"OpenBao's core. The encrypted values can be recovered in the event of " +
			"failure or discarded after success. See the -backup-delete and " +
			"-backup-retrieve options for more information. This option only " +
			"applies when the existing unseal or recovery keys were PGP encrypted.",
	})

	f.BoolVar(&BoolVar{
		Name:    "backup-delete",
		Target:  &c.flagBackupDelete,
		Default: false,
		Usage:   "Delete any stored backup unseal or recovery keys.",
	})

	f.BoolVar(&BoolVar{
		Name:    "backup-retrieve",
		Target:  &c.flagBackupRetrieve,
		Default: false,
		Usage: "Retrieve the backed-up unseal or recovery keys. This option is only available " +
			"if the PGP keys were provided and the backup has not been deleted.",
	})

	return set
}

func (c *OperatorRotateKeysCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *OperatorRotateKeysCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorRotateKeysCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 1 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0-1, got %d)", len(args)))
		return 1
	}

	// Create the client
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	switch {
	case c.flagBackupDelete:
		return c.backupDelete(client)
	case c.flagBackupRetrieve:
		return c.backupRetrieve(client)
	case c.flagCancel:
		return c.cancel(client)
	case c.flagInit:
		return c.init(client)
	case c.flagStatus:
		return c.status(client)
	default:
		// If there are no other flags, prompt for an unseal key.
		key := ""
		if len(args) > 0 {
			key = strings.TrimSpace(args[0])
		}
		return c.provide(client, key)
	}
}

// init starts the rotation process.
func (c *OperatorRotateKeysCommand) init(client *api.Client) int {
	// Handle the different API requests
	var fn func(*api.RotateInitRequest) (*api.RotateStatusResponse, error)
	keyTypeRequired := keyTypeUnseal
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		fn = client.Sys().RotateRootInit
	case "recovery", "hsm":
		keyTypeRequired = keyTypeRecovery
		fn = client.Sys().RotateRecoveryInit
	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	// Make the request
	resp, err := fn(&api.RotateInitRequest{
		SecretShares:        c.flagKeyShares,
		SecretThreshold:     c.flagKeyThreshold,
		PGPKeys:             c.flagPGPKeys,
		Backup:              c.flagBackup,
		RequireVerification: c.flagVerify,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing rotation: %s", err))
		return 2
	}

	if resp.Complete {
		// if the rotation is complete, meaning we've immediately
		// returned the unseal (recovery) keys, print them out
		if len(c.flagPGPKeys) == 0 {
			if Format(c.UI) == "table" {
				c.UI.Warn(wrapAtLength(
					fmt.Sprintf("WARNING! If you lose the keys, there "+
						"is no recovery. Consider rerunning this operation and "+
						"re-initializing with the -pgp-keys flag to protect the "+
						"returned %s keys along with -backup to allow recovery "+
						"of the encrypted keys in case of emergency. You can "+
						"delete the stored keys later using the -delete flag.",
						strings.ToLower(keyTypeRequired))))
				c.UI.Output("")
			}
		}
		if len(c.flagPGPKeys) > 0 && !c.flagBackup {
			if Format(c.UI) == "table" {
				c.UI.Warn(wrapAtLength(
					fmt.Sprintf("WARNING! You've used PGP keys for "+
						"encryption of the resulting %s keys, but you did not "+
						"enable the option to backup the keys to OpenBao's core. "+
						"If you lose the encrypted keys you will not be able to "+
						"recover them. Consider rerunning this operation and "+
						"re-initializing with -backup to allow recovery of the "+
						"encrypted unseal keys in case of emergency. You can "+
						"delete the stored keys later using the -delete flag.",
						strings.ToLower(keyTypeRequired))))
				c.UI.Output("")
			}
		}

		return c.printUnsealKeys(client, resp, &api.RotateUpdateResponse{
			Complete:        resp.Complete,
			Keys:            resp.Keys,
			KeysB64:         resp.KeysB64,
			Backup:          resp.Backup,
			PGPFingerprints: resp.PGPFingerprints,
		})
	}

	// Print warnings about recovery, etc.
	if len(c.flagPGPKeys) == 0 {
		if Format(c.UI) == "table" {
			c.UI.Warn(wrapAtLength(
				fmt.Sprintf("WARNING! If you lose the keys after they are "+
					"returned, there is no recovery. Consider canceling this "+
					"operation and re-initializing with the -pgp-keys flag to protect "+
					"the returned %s keys along with -backup to allow recovery of the "+
					"encrypted keys in case of emergency. You can delete the stored "+
					"keys later using the -delete flag.",
					strings.ToLower(keyTypeRequired))))
			c.UI.Output("")
		}
	}
	if len(c.flagPGPKeys) > 0 && !c.flagBackup {
		if Format(c.UI) == "table" {
			c.UI.Warn(wrapAtLength(
				fmt.Sprintf("WARNING! You are using PGP keys for encryption "+
					"of resulting %s keys, but you did not enable the option to backup "+
					"the keys to OpenBao's core. If you lose the encrypted keys after "+
					"they are returned, you will not be able to recover them. Consider "+
					"canceling this operation and re-running with -backup to allow "+
					"recovery of the encrypted unseal keys in case of emergency. You "+
					"can delete the stored keys later using the -delete flag.",
					strings.ToLower(keyTypeRequired))))
			c.UI.Output("")
		}
	}

	return c.printStatus(resp)
}

// cancel is used to abort the rotation process.
func (c *OperatorRotateKeysCommand) cancel(client *api.Client) int {
	// Handle the different API requests
	var fn func() error
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		fn = client.Sys().RotateRootCancel
		if c.flagVerify {
			fn = client.Sys().RotateRootVerificationCancel
		}
	case "recovery", "hsm":
		fn = client.Sys().RotateRecoveryCancel
		if c.flagVerify {
			fn = client.Sys().RotateRecoveryVerificationCancel
		}

	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	// Make the request
	if err := fn(); err != nil {
		c.UI.Error(fmt.Sprintf("Error canceling rotation: %s", err))
		return 2
	}

	c.UI.Output("Success! Canceled rotation (if it was started)")
	return 0
}

// provide prompts the user for the seal key and posts it to the update root
// endpoint. If this is the last unseal, this function outputs it.
func (c *OperatorRotateKeysCommand) provide(client *api.Client, key string) int {
	var statusFn func() (interface{}, error)
	var updateFn func(string, string) (interface{}, error)
	keyTypeRequired := keyTypeUnseal
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		statusFn = func() (interface{}, error) {
			return client.Sys().RotateRootStatus()
		}
		updateFn = func(s1 string, s2 string) (interface{}, error) {
			return client.Sys().RotateRootUpdate(s1, s2)
		}
		if c.flagVerify {
			statusFn = func() (interface{}, error) {
				return client.Sys().RotateRootVerificationStatus()
			}
			updateFn = func(s1 string, s2 string) (interface{}, error) {
				return client.Sys().RotateRootVerificationUpdate(s1, s2)
			}
		}
	case "recovery", "hsm":
		keyTypeRequired = keyTypeRecovery
		statusFn = func() (interface{}, error) {
			return client.Sys().RotateRecoveryStatus()
		}
		updateFn = func(s1 string, s2 string) (interface{}, error) {
			return client.Sys().RotateRecoveryUpdate(s1, s2)
		}
		if c.flagVerify {
			statusFn = func() (interface{}, error) {
				return client.Sys().RotateRecoveryVerificationStatus()
			}
			updateFn = func(s1 string, s2 string) (interface{}, error) {
				return client.Sys().RotateRecoveryVerificationUpdate(s1, s2)
			}
		}
	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	status, err := statusFn()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting rotation status: %s", err))
		return 2
	}

	var started bool
	var nonce string

	switch status := status.(type) {
	case *api.RotateStatusResponse:
		stat := status
		started = stat.Started
		nonce = stat.Nonce
	case *api.RotateVerificationStatusResponse:
		stat := status
		started = stat.Started
		nonce = stat.Nonce
	default:
		c.UI.Error("Unknown status type")
		return 1
	}

	// Verify a root token generation is in progress. If there is not one in
	// progress, return an error instructing the user to start one.
	if !started {
		c.UI.Error(wrapAtLength(
			"No rotation is in progress. Start a rotation process by running " +
				"\"bao operator rotate-keys -init\"."))
		return 1
	}

	switch key {
	case "-": // Read from stdin
		nonce = c.flagNonce

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
		if c.flagNonInteractive {
			c.UI.Error(wrapAtLength("Refusing to read from stdin with -non-interactive specified; specify nonce via the -nonce flag"))
			return 1
		}

		w := getWriterFromUI(c.UI)
		_, err := fmt.Fprintf(w, "rotation nonce: %s\n", nonce)
		if err != nil {
			c.UI.Error("failed to output rotation nonce")
		}

		_, err = fmt.Fprintf(w, "%s Key (will be hidden): \n", keyTypeRequired)
		if err != nil {
			c.UI.Error("failed to output key type")
		}

		key, err = password.Read(os.Stdin)
		if err != nil {
			if err == password.ErrInterrupted {
				c.UI.Error("user canceled")
				return 1
			}

			c.UI.Error(wrapAtLength(fmt.Sprintf("An error occurred attempting to "+
				"ask for the %s key. The raw error message is shown below, but "+
				"usually this is because you attempted to pipe a value into the "+
				"command or you are executing outside of a terminal (tty). If you "+
				"want to pipe the value, pass \"-\" as the argument to read from "+
				"stdin. The raw error was: %s", strings.ToLower(keyTypeRequired), err)))
			return 1
		}
	default: // Supplied directly as an arg
		nonce = c.flagNonce
	}

	// Trim any whitespace from they key, especially since we might have
	// prompted the user for it.
	key = strings.TrimSpace(key)

	// Verify we have a nonce value
	if nonce == "" {
		c.UI.Error("Missing nonce value: specify it via the -nonce flag")
		return 1
	}

	// Provide the key, this may potentially complete the update
	resp, err := updateFn(key, nonce)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error posting unseal key: %s", err))
		return 2
	}

	var complete bool
	var mightContainUnsealKeys bool

	switch resp := resp.(type) {
	case *api.RotateUpdateResponse:
		complete = resp.Complete
		mightContainUnsealKeys = true
	case *api.RotateVerificationUpdateResponse:
		complete = resp.Complete
	default:
		c.UI.Error("Unknown update response type")
		return 1
	}

	if !complete {
		return c.status(client)
	}

	if mightContainUnsealKeys {
		return c.printUnsealKeys(client, status.(*api.RotateStatusResponse),
			resp.(*api.RotateUpdateResponse))
	}

	c.UI.Output(wrapAtLength("Rotation verification successful. The rotation is complete and the new keys are now active."))
	return 0
}

// status is used just to fetch and dump the status.
func (c *OperatorRotateKeysCommand) status(client *api.Client) int {
	// Handle the different API requests
	var fn func() (interface{}, error)
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		fn = func() (interface{}, error) {
			return client.Sys().RotateRootStatus()
		}
		if c.flagVerify {
			fn = func() (interface{}, error) {
				return client.Sys().RotateRootVerificationStatus()
			}
		}
	case "recovery", "hsm":
		fn = func() (interface{}, error) {
			return client.Sys().RotateRecoveryStatus()
		}
		if c.flagVerify {
			fn = func() (interface{}, error) {
				return client.Sys().RotateRecoveryVerificationStatus()
			}
		}
	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	// Make the request
	status, err := fn()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading rotate status: %s", err))
		return 2
	}

	return c.printStatus(status)
}

// backupRetrieve retrieves the stored backup keys.
func (c *OperatorRotateKeysCommand) backupRetrieve(client *api.Client) int {
	// Handle the different API requests
	var fn func() (*api.RotateRetrieveResponse, error)
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		fn = client.Sys().RotateRootRetrieveBackup
	case "recovery", "hsm":
		fn = client.Sys().RotateRecoveryRetrieveBackup
	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	// Make the request
	storedKeys, err := fn()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error retrieving rotation stored keys: %s", err))
		return 2
	}

	secret := &api.Secret{
		Data: structs.New(storedKeys).Map(),
	}

	return OutputSecret(c.UI, secret)
}

// backupDelete deletes the stored backup keys.
func (c *OperatorRotateKeysCommand) backupDelete(client *api.Client) int {
	// Handle the different API requests
	var fn func() error
	switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
	case "barrier":
		fn = client.Sys().RotateRootDeleteBackup
	case "recovery", "hsm":
		fn = client.Sys().RotateRecoveryDeleteBackup
	default:
		c.UI.Error(fmt.Sprintf("Unknown target: %s", c.flagTarget))
		return 1
	}

	// Make the request
	if err := fn(); err != nil {
		c.UI.Error(fmt.Sprintf("Error deleting rotation stored keys: %s", err))
		return 2
	}

	c.UI.Output("Success! Deleted stored keys (if they existed)")
	return 0
}

// printStatus dumps the status to output
func (c *OperatorRotateKeysCommand) printStatus(in interface{}) int {
	out := []string{}
	out = append(out, "Key | Value")

	switch in := in.(type) {
	case *api.RotateStatusResponse:
		status := in
		out = append(out, fmt.Sprintf("Nonce | %s", status.Nonce))
		out = append(out, fmt.Sprintf("Started | %t", status.Started))
		if status.Started {
			if status.Progress == status.Required {
				out = append(out, fmt.Sprintf("Rotation Progress | %d/%d (verification in progress)", status.Progress, status.Required))
			} else {
				out = append(out, fmt.Sprintf("Rotation Progress | %d/%d", status.Progress, status.Required))
			}
			out = append(out, fmt.Sprintf("New Shares | %d", status.N))
			out = append(out, fmt.Sprintf("New Threshold | %d", status.T))
			out = append(out, fmt.Sprintf("Verification Required | %t", status.VerificationRequired))
			if status.VerificationNonce != "" {
				out = append(out, fmt.Sprintf("Verification Nonce | %s", status.VerificationNonce))
			}
		}
		if len(status.PGPFingerprints) > 0 {
			out = append(out, fmt.Sprintf("PGP Fingerprints | %s", status.PGPFingerprints))
			out = append(out, fmt.Sprintf("Backup | %t", status.Backup))
		}
	case *api.RotateVerificationStatusResponse:
		status := in
		out = append(out, fmt.Sprintf("Started | %t", status.Started))
		out = append(out, fmt.Sprintf("New Shares | %d", status.N))
		out = append(out, fmt.Sprintf("New Threshold | %d", status.T))
		out = append(out, fmt.Sprintf("Verification Nonce | %s", status.Nonce))
		out = append(out, fmt.Sprintf("Verification Progress | %d/%d", status.Progress, status.T))
	default:
		c.UI.Error("Unknown status type")
		return 1
	}

	switch Format(c.UI) {
	case "table":
		c.UI.Output(tableOutput(out, nil))
		return 0
	default:
		return OutputData(c.UI, in)
	}
}

func (c *OperatorRotateKeysCommand) printUnsealKeys(client *api.Client, status *api.RotateStatusResponse, resp *api.RotateUpdateResponse) int {
	switch Format(c.UI) {
	case "table":
	default:
		return OutputData(c.UI, resp)
	}

	// Space between the key prompt, if any, and the output
	c.UI.Output("")

	// Provide the keys
	var haveB64 bool
	if resp.KeysB64 != nil && len(resp.KeysB64) == len(resp.Keys) {
		haveB64 = true
	}
	for i, key := range resp.Keys {
		if len(resp.PGPFingerprints) > 0 {
			if haveB64 {
				c.UI.Output(fmt.Sprintf("Key %d fingerprint: %s; value: %s", i+1, resp.PGPFingerprints[i], resp.KeysB64[i]))
			} else {
				c.UI.Output(fmt.Sprintf("Key %d fingerprint: %s; value: %s", i+1, resp.PGPFingerprints[i], key))
			}
		} else {
			if haveB64 {
				c.UI.Output(fmt.Sprintf("Key %d: %s", i+1, resp.KeysB64[i]))
			} else {
				c.UI.Output(fmt.Sprintf("Key %d: %s", i+1, key))
			}
		}
	}

	if resp.Nonce != "" {
		c.UI.Output("")
		c.UI.Output(fmt.Sprintf("Operation nonce: %s", resp.Nonce))
	}

	if len(resp.PGPFingerprints) > 0 && resp.Backup {
		c.UI.Output("")
		switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
		case "barrier":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"The encrypted unseal keys are backed up to \"core/unseal-keys-backup\" " +
					"in the storage backend. Remove these keys at any time using " +
					"\"bao operator rotate-keys -backup-delete\". OpenBao does not automatically " +
					"remove these keys.",
			)))
		case "recovery", "hsm":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"The encrypted recovery keys are backed up to \"core/recovery-keys-backup\" " +
					"in the storage backend. Remove these keys at any time using " +
					"\"bao operator rotate-keys -backup-delete -target=recovery\". OpenBao does not automatically " +
					"remove these keys.",
			)))
		}
	}

	switch status.VerificationRequired {
	case false:
		c.UI.Output("")
		switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
		case "barrier":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"OpenBao unseal keys rotated to %d key shares and a key threshold of %d. Please "+
					"securely distribute the key shares printed above. When OpenBao is "+
					"re-sealed, restarted, or stopped, you must supply at least %d of "+
					"these keys to unseal it before it can start servicing requests.",
				status.N,
				status.T,
				status.T)))
		case "recovery", "hsm":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"OpenBao recovery keys rotated to %d key shares and a key threshold of %d. Please "+
					"securely distribute the key shares printed above.",
				status.N,
				status.T)))
		}

	default:
		c.UI.Output("")
		var warningText string
		switch strings.ToLower(strings.TrimSpace(c.flagTarget)) {
		case "barrier":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"OpenBao has created a new unseal key, split into %d key shares and a key threshold "+
					"of %d. These will not be active until after verification is complete. "+
					"Please securely distribute the key shares printed above. When OpenBao "+
					"is re-sealed, restarted, or stopped, you must supply at least %d of "+
					"these keys to unseal it before it can start servicing requests.",
				status.N,
				status.T,
				status.T)))
			warningText = "unseal"
		case "recovery", "hsm":
			c.UI.Output(wrapAtLength(fmt.Sprintf(
				"OpenBao has created a new recovery key, split into %d key shares and a key threshold "+
					"of %d. These will not be active until after verification is complete. "+
					"Please securely distribute the key shares printed above.",
				status.N,
				status.T)))
			warningText = "authenticate with"

		}
		c.UI.Output("")
		c.UI.Warn(wrapAtLength(fmt.Sprintf(
			"Again, these key shares are _not_ valid until verification is performed. "+
				"Do not lose or discard your current key shares until after verification "+
				"is complete or you will be unable to %s OpenBao. If you cancel the "+
				"rotation process or seal OpenBao before verification is complete the new "+
				"shares will be discarded and the current shares will remain valid.", warningText)))
		c.UI.Output("")
		c.UI.Warn(wrapAtLength(
			"The current verification status, including initial nonce, is shown below.",
		))
		c.UI.Output("")

		c.flagVerify = true
		return c.status(client)
	}

	return 0
}
