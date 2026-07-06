// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/plugins/database/remote-db-plugin/bootstrap"
	"github.com/posener/complete"
)

// RelayInitCommand initializes the hub's trust-bootstrap state and prints the
// `bao relay join` invocation to run on each spoke. This is the kubeadm-style
// counterpart to `kubeadm init`.
type RelayInitCommand struct {
	*BaseCommand

	flagMount         string
	flagHubEndpoint   string
	flagHubDNSSANs    []string
	flagHubIPSANs     []string
	flagAllowedSpoke  string
	flagTokenTTL      string
	flagDescription   string
	flagForce         bool
	flagPrintJoinOnly bool
}

var (
	_ cli.Command             = (*RelayInitCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayInitCommand)(nil)
)

func (c *RelayInitCommand) Synopsis() string {
	return "Initialize the hub for spoke joins and print a join command"
}

func (c *RelayInitCommand) Help() string {
	helpText := `
Usage: bao relay init [options]

  Initializes the hub side of the OpenBao hub-and-spoke remote database plugin.
  This command:

    1. Mounts the 'relay/' backend if it is not already mounted.
    2. Generates a self-signed spoke certificate authority and a hub TLS cert
       (unless already initialized; pass -force to regenerate).
    3. Creates a short-lived bootstrap token.
    4. Prints a 'bao relay join' command to run on each spoke.

  The hub TLS cert is presented by the proxy gRPC listener. Spokes verify it
  using the SPKI pin printed in the join command.

  Example:

      $ bao relay init \
          -hub-endpoint=hub.example.com:50053 \
          -hub-dns-sans=hub.example.com \
          -allowed-spoke-name=spoke-1

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *RelayInitCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "mount",
		Target:  &c.flagMount,
		Default: "relay",
		Usage:   "Mount path of the relay backend.",
	})
	f.StringVar(&StringVar{
		Name:    "hub-endpoint",
		Target:  &c.flagHubEndpoint,
		Default: "",
		Usage:   "host:port the proxy gRPC server advertises to spokes (required).",
	})
	f.StringSliceVar(&StringSliceVar{
		Name:    "hub-dns-sans",
		Target:  &c.flagHubDNSSANs,
		Default: nil,
		Usage:   "DNS SANs to include on the hub TLS cert.",
	})
	f.StringSliceVar(&StringSliceVar{
		Name:    "hub-ip-sans",
		Target:  &c.flagHubIPSANs,
		Default: nil,
		Usage:   "IP SANs to include on the hub TLS cert.",
	})
	f.StringVar(&StringVar{
		Name:    "allowed-spoke-name",
		Target:  &c.flagAllowedSpoke,
		Default: "",
		Usage: "Restrict the printed token to a specific spoke identity. " +
			"Empty (default) means any spoke name may join with this token. " +
			"Spoke names are case-sensitive (lowercase by convention).",
	})
	f.StringVar(&StringVar{
		Name:    "token-ttl",
		Target:  &c.flagTokenTTL,
		Default: "24h",
		Usage:   "Bootstrap token lifetime.",
	})
	f.StringVar(&StringVar{
		Name:    "description",
		Target:  &c.flagDescription,
		Default: "",
		Usage:   "Free-form description recorded with the token.",
	})
	f.BoolVar(&BoolVar{
		Name:    "force",
		Target:  &c.flagForce,
		Default: false,
		Usage:   "Regenerate the CA + hub cert even if one already exists.",
	})
	f.BoolVar(&BoolVar{
		Name:    "print-join-only",
		Target:  &c.flagPrintJoinOnly,
		Default: false,
		Usage:   "Skip CA init; only create a token and print a join command.",
	})

	return set
}

func (c *RelayInitCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayInitCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayInitCommand) Run(args []string) int {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.flagHubEndpoint == "" && !c.flagPrintJoinOnly {
		c.UI.Error("-hub-endpoint is required for first-time init")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	mount := strings.TrimSuffix(c.flagMount, "/")

	if !c.flagPrintJoinOnly {
		if err := ensureRelayMount(client, mount); err != nil {
			c.UI.Error(fmt.Sprintf("Mounting %s/: %s", mount, err))
			return 2
		}

		caData, err := initOrFetchCA(client, mount, c)
		if err != nil {
			c.UI.Error(fmt.Sprintf("CA init: %s", err))
			return 2
		}
		c.UI.Info(fmt.Sprintf("Hub identity ready (hub_endpoint=%s)", caData["hub_endpoint"]))
	}

	tokenData, tokenWarnings, hubEndpoint, caHash, err := createBootstrapToken(client, mount, c)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Create token: %s", err))
		return 2
	}

	c.UI.Output("")
	c.UI.Output("Hub initialized. Run the following on each spoke:")
	c.UI.Output("")
	c.UI.Output(fmt.Sprintf("  BAO_ADDR=%s \\", client.Address()))
	c.UI.Output("  bao relay join \\")
	c.UI.Output(fmt.Sprintf("      -hub-addr=%s \\", hubEndpoint))
	c.UI.Output(fmt.Sprintf("      -hub-cert-hash=%s \\", caHash))
	c.UI.Output(fmt.Sprintf("      -token=%s \\", tokenData["token"]))
	if c.flagAllowedSpoke != "" {
		c.UI.Output(fmt.Sprintf("      -spoke-name=%s", c.flagAllowedSpoke))
	} else {
		c.UI.Output("      -spoke-name=<choose-a-name>")
	}
	c.UI.Output("")
	for _, w := range tokenWarnings {
		c.UI.Warn("WARNING: " + w)
	}
	return 0
}

func ensureRelayMount(client *api.Client, mount string) error {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}
	if _, ok := mounts[mount+"/"]; ok {
		return nil
	}
	return client.Sys().Mount(mount+"/", &api.MountInput{
		Type:        "relay",
		Description: "OpenBao hub-and-spoke trust-bootstrap state",
	})
}

func initOrFetchCA(client *api.Client, mount string, c *RelayInitCommand) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"hub_endpoint": c.flagHubEndpoint,
		"force":        c.flagForce,
	}
	if len(c.flagHubDNSSANs) > 0 {
		body["hub_dns_sans"] = c.flagHubDNSSANs
	}
	if len(c.flagHubIPSANs) > 0 {
		body["hub_ip_sans"] = c.flagHubIPSANs
	}
	// Try ca/init first. If it returns "already initialized" and -force was not
	// passed, fall back to ca/info — this makes the command idempotent.
	resp, err := client.Logical().Write(mount+"/ca/init", body)
	if err == nil {
		return resp.Data, nil
	}
	if !c.flagForce && isAlreadyInitialized(err) {
		info, infoErr := client.Logical().Read(mount + "/ca/info")
		if infoErr != nil {
			return nil, fmt.Errorf("ca already initialized but info read failed: %w", infoErr)
		}
		if info == nil {
			return nil, errors.New("ca/info returned nothing")
		}
		return info.Data, nil
	}
	return nil, err
}

func createBootstrapToken(client *api.Client, mount string, c *RelayInitCommand) (map[string]interface{}, []string, string, string, error) {
	body := map[string]interface{}{
		"ttl":         c.flagTokenTTL,
		"description": c.flagDescription,
	}
	if c.flagAllowedSpoke != "" {
		body["allowed_spoke_name"] = c.flagAllowedSpoke
	}
	resp, err := client.Logical().Write(mount+"/bootstrap-tokens", body)
	if err != nil {
		return nil, nil, "", "", err
	}
	info, err := client.Logical().Read(mount + "/ca/info")
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("read ca/info: %w", err)
	}
	if info == nil {
		return nil, nil, "", "", errors.New("ca not initialized")
	}
	hubEndpoint, _ := info.Data["hub_endpoint"].(string)
	caHash, _ := info.Data["ca_cert_hash"].(string)
	if hubEndpoint == "" || caHash == "" {
		return nil, nil, "", "", errors.New("ca/info missing hub_endpoint or ca_cert_hash")
	}
	return resp.Data, resp.Warnings, hubEndpoint, caHash, nil
}

// isAlreadyInitialized matches the canonical prefix the relay backend
// returns from ca/init when force is not set. The constant is exported by
// the bootstrap package so the CLI and the backend reference the same
// source of truth instead of pattern-matching a free-floating string. It is
// still a substring check (api.Client error formatting may prepend HTTP
// status text), but the substring itself is no longer hardcoded here.
func isAlreadyInitialized(err error) bool {
	return err != nil && strings.Contains(err.Error(), bootstrap.MsgCAAlreadyInitialized)
}
