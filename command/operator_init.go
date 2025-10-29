// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*OperatorInitCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorInitCommand)(nil)
)

type OperatorInitCommand struct {
	*BaseCommand

	flagStatus          bool
	flagKeyShares       int
	flagKeyThreshold    int
	flagPGPKeys         []string
	flagRootTokenPGPKey string

	// Auto Unseal
	flagRecoveryShares    int
	flagRecoveryThreshold int
	flagRecoveryPGPKeys   []string
}

const (
	defKeyShares         = 5
	defKeyThreshold      = 3
	defRecoveryShares    = 5
	defRecoveryThreshold = 3
)

func (c *OperatorInitCommand) Synopsis() string {
	return "Initializes a server"
}

func (c *OperatorInitCommand) Help() string {
	helpText := `
Usage: bao operator init [options]

  Initializes an OpenBao server. Initialization is the process by which
  OpenBao's storage backend is prepared to receive data. Since OpenBao servers
  share the same storage backend in HA mode, you only need to initialize one
  OpenBao instance to initialize the storage backend.

  During initialization, OpenBao generates an in-memory root key and applies
  Shamir's secret sharing algorithm to disassemble that root key into a
  configuration number of key shares such that a configurable subset of those
  key shares must come together to regenerate the root key. These keys are
  often called "unseal keys" in OpenBao's documentation.

  This command cannot be run against an already-initialized OpenBao cluster.

  Start initialization with the default options:

      $ bao operator init

  Initialize, but encrypt the unseal keys with pgp keys:

      $ bao operator init \
          -key-shares=3 \
          -key-threshold=2 \
          -pgp-keys="keybase:hashicorp,keybase:jefferai,keybase:sethvargo"

  Encrypt the initial root token using a pgp key:

      $ bao operator init -root-token-pgp-key="keybase:hashicorp"

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorInitCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	// Common Options
	f := set.NewFlagSet("Common Options")

	f.BoolVar(&BoolVar{
		Name:    "status",
		Target:  &c.flagStatus,
		Default: false,
		Usage: "Print the current initialization status. An exit code of 0 means " +
			"the OpenBao is already initialized. An exit code of 1 means an error " +
			"occurred. An exit code of 2 means the OpenBao is not initialized.",
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

	f.VarFlag(&VarFlag{
		Name:       "root-token-pgp-key",
		Value:      (*pgpkeys.PubKeyFileFlag)(&c.flagRootTokenPGPKey),
		Completion: complete.PredictAnything,
		Usage: "Path to a file on disk containing a binary or base64-encoded " +
			"public PGP key. This can also be specified as a Keybase username " +
			"using the format \"keybase:<username>\". When supplied, the generated " +
			"root token will be encrypted and base64-encoded with the given public " +
			"key.",
	})

	// Auto Unseal Options
	f = set.NewFlagSet("Auto Unseal Options")

	f.IntVar(&IntVar{
		Name:       "recovery-shares",
		Target:     &c.flagRecoveryShares,
		Completion: complete.PredictAnything,
		Default:    defRecoveryShares,
		Usage: "Number of key shares to split the recovery key into. " +
			"This is only used in Auto Unseal mode.",
	})

	f.IntVar(&IntVar{
		Name:       "recovery-threshold",
		Target:     &c.flagRecoveryThreshold,
		Completion: complete.PredictAnything,
		Default:    defRecoveryThreshold,
		Usage: "Number of key shares required to reconstruct the recovery key. " +
			"This is only used in Auto Unseal mode.",
	})

	f.VarFlag(&VarFlag{
		Name:       "recovery-pgp-keys",
		Value:      (*pgpkeys.PubKeyFilesFlag)(&c.flagRecoveryPGPKeys),
		Completion: complete.PredictAnything,
		Usage: "Behaves like -pgp-keys, but for the recovery key shares. This " +
			"is only used in Auto Unseal mode.",
	})

	return set
}

func (c *OperatorInitCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *OperatorInitCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorInitCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	// -output-curl string returns curl command for seal status
	// setting this to false and then setting actual value after reading seal status
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	// -output-policy string returns minimum required policy HCL for seal status
	// setting this to false and then setting actual value after reading seal status
	outputPolicy := client.OutputPolicy()
	client.SetOutputPolicy(false)

	// Set defaults based on use of auto unseal seal
	sealInfo, err := client.Sys().SealStatus()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	client.SetOutputCurlString(currentOutputCurlString)
	client.SetOutputPolicy(outputPolicy)

	// for barrier seals use the default value of key shares and key threshold,
	// as we do not support 0 as a valid value for those
	if !sealInfo.RecoverySeal {
		if c.flagKeyShares == 0 {
			c.flagKeyShares = defKeyShares
		}
		if c.flagKeyThreshold == 0 {
			c.flagKeyThreshold = defKeyThreshold
		}
		// override default values for recovery shares as it's not supported
		c.flagRecoveryShares = 0
		c.flagRecoveryThreshold = 0
	}

	// Build the initial init request
	initReq := &api.InitRequest{
		SecretShares:    c.flagKeyShares,
		SecretThreshold: c.flagKeyThreshold,
		PGPKeys:         c.flagPGPKeys,
		RootTokenPGPKey: c.flagRootTokenPGPKey,

		RecoveryShares:    c.flagRecoveryShares,
		RecoveryThreshold: c.flagRecoveryThreshold,
		RecoveryPGPKeys:   c.flagRecoveryPGPKeys,
	}

	// Check auto mode
	switch {
	case c.flagStatus:
		return c.status(client)
	default:
		return c.init(client, initReq)
	}
}

func (c *OperatorInitCommand) init(client *api.Client, req *api.InitRequest) int {
	resp, err := client.Sys().Init(req)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
	default:
		return OutputData(c.UI, newMachineInit(req, resp))
	}

	for i, key := range resp.Keys {
		if resp.KeysB64 != nil && len(resp.KeysB64) == len(resp.Keys) {
			c.UI.Output(fmt.Sprintf("Unseal Key %d: %s", i+1, resp.KeysB64[i]))
		} else {
			c.UI.Output(fmt.Sprintf("Unseal Key %d: %s", i+1, key))
		}
	}
	for i, key := range resp.RecoveryKeys {
		if resp.RecoveryKeysB64 != nil && len(resp.RecoveryKeysB64) == len(resp.RecoveryKeys) {
			c.UI.Output(fmt.Sprintf("Recovery Key %d: %s", i+1, resp.RecoveryKeysB64[i]))
		} else {
			c.UI.Output(fmt.Sprintf("Recovery Key %d: %s", i+1, key))
		}
	}

	c.UI.Output("")
	c.UI.Output(fmt.Sprintf("Initial Root Token: %s", resp.RootToken))

	if len(resp.Keys) > 0 {
		c.UI.Output("")
		c.UI.Output(wrapAtLength(fmt.Sprintf(
			"Vault initialized with %d key shares and a key threshold of %d. Please "+
				"securely distribute the key shares printed above. When the Vault is "+
				"re-sealed, restarted, or stopped, you must supply at least %d of "+
				"these keys to unseal it before it can start servicing requests.",
			req.SecretShares,
			req.SecretThreshold,
			req.SecretThreshold)))

		c.UI.Output("")
		c.UI.Output(wrapAtLength(fmt.Sprintf(
			"Vault does not store the generated root key. Without at least %d "+
				"keys to reconstruct the root key, Vault will remain permanently "+
				"sealed!",
			req.SecretThreshold)))

		c.UI.Output("")
		c.UI.Output(wrapAtLength(
			"It is possible to generate new unseal keys, provided you have a quorum " +
				"of existing unseal keys shares. See \"bao operator rotate-keys\" for " +
				"more information."))
	} else {
		c.UI.Output("")
		c.UI.Output("Success! Vault is initialized")
	}

	if len(resp.RecoveryKeys) > 0 {
		c.UI.Output("")
		c.UI.Output(wrapAtLength(fmt.Sprintf(
			"Recovery key initialized with %d key shares and a key threshold of %d. "+
				"Please securely distribute the key shares printed above.",
			req.RecoveryShares,
			req.RecoveryThreshold)))
	}

	return 0
}

// status inspects the init status of vault and returns an appropriate error
// code and message.
func (c *OperatorInitCommand) status(client *api.Client) int {
	inited, err := client.Sys().InitStatus()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error checking init status: %s", err))
		return 1 // Normally we'd return 2, but 2 means something special here
	}

	errorCode := 0

	if !inited {
		errorCode = 2
	}

	switch Format(c.UI) {
	case "table":
		if inited {
			c.UI.Output("Vault is initialized")
		} else {
			c.UI.Output("Vault is not initialized")
		}
	default:
		data := api.InitStatusResponse{Initialized: inited}
		OutputData(c.UI, data)
	}

	return errorCode
}

// machineInit is used to output information about the init command.
type machineInit struct {
	UnsealKeysB64     []string `json:"unseal_keys_b64"`
	UnsealKeysHex     []string `json:"unseal_keys_hex"`
	UnsealShares      int      `json:"unseal_shares"`
	UnsealThreshold   int      `json:"unseal_threshold"`
	RecoveryKeysB64   []string `json:"recovery_keys_b64"`
	RecoveryKeysHex   []string `json:"recovery_keys_hex"`
	RecoveryShares    int      `json:"recovery_keys_shares"`
	RecoveryThreshold int      `json:"recovery_keys_threshold"`
	RootToken         string   `json:"root_token"`
}

func newMachineInit(req *api.InitRequest, resp *api.InitResponse) *machineInit {
	init := &machineInit{}

	init.UnsealKeysHex = slices.Clone(resp.Keys)
	init.UnsealKeysB64 = slices.Clone(resp.KeysB64)

	// If we don't get a set of keys back, it means that we are storing the keys,
	// so the key shares and threshold has been set to 1.
	if len(resp.Keys) == 0 {
		init.UnsealShares = 1
		init.UnsealThreshold = 1
	} else {
		init.UnsealShares = req.SecretShares
		init.UnsealThreshold = req.SecretThreshold
	}

	init.RecoveryKeysHex = slices.Clone(resp.RecoveryKeys)
	init.RecoveryKeysB64 = slices.Clone(resp.RecoveryKeysB64)

	init.RecoveryShares = req.RecoveryShares
	init.RecoveryThreshold = req.RecoveryThreshold

	init.RootToken = resp.RootToken

	return init
}
