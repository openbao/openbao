// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

// --- bao relay ca (parent) ---------------------------------------------------

type RelayCACommand struct {
	*BaseCommand
}

var _ cli.Command = (*RelayCACommand)(nil)

func (c *RelayCACommand) Synopsis() string {
	return "Inspect or rotate the hub spoke-CA"
}

func (c *RelayCACommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay ca <subcommand> [options]

Subcommands:
  status   Show CA + hub cert metadata, expiry, and listener state
  rotate   Re-issue the hub TLS cert; with -full, rotate the CA itself
`)
}
func (c *RelayCACommand) Run(args []string) int { return cli.RunResultHelp }

// --- bao relay ca status -----------------------------------------------------

type RelayCAStatusCommand struct {
	*BaseCommand

	flagMount string
}

var (
	_ cli.Command             = (*RelayCAStatusCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayCAStatusCommand)(nil)
)

func (c *RelayCAStatusCommand) Synopsis() string { return "Show CA + hub cert metadata" }
func (c *RelayCAStatusCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay ca status [options]

  Shows the spoke-CA and hub TLS cert metadata: subjects, expiry dates,
  SANs, SPKI pin, and the port the proxy gRPC listener is bound to.

` + c.Flags().Help())
}

func (c *RelayCAStatusCommand) Flags() *FlagSets {
	// FlagSetOutputFormat brings in the shared `-format` flag so this command
	// honors `-format=json` like the rest of the bao CLI. With format != table
	// we round-trip the raw ca/info data through OutputData; with format=table
	// (the default) we keep the human-friendly key/value layout below.
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	return set
}

func (c *RelayCAStatusCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayCAStatusCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayCAStatusCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	resp, err := client.Logical().Read(strings.Trim(c.flagMount, "/") + "/ca/info")
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	if resp == nil {
		c.UI.Error("CA not initialized; run `bao relay init`")
		return 2
	}
	d := resp.Data

	// Honor -format=json|yaml by handing the raw map to the shared formatter.
	// The default "table" format keeps the human-friendly key/value layout
	// below, which is more useful at the terminal than the generic map dump.
	if format := Format(c.UI); format != "" && format != "table" {
		return OutputData(c.UI, d)
	}

	caNotAfter := asUnix(d["ca_not_after"])
	hubNotAfter := asUnix(d["hub_cert_not_after"])
	listenerPort := asUnix(d["listener_port"])

	c.UI.Output(fmt.Sprintf("ca_subject:        %s", str(d["ca_subject"])))
	c.UI.Output(fmt.Sprintf("ca_cert_hash:      %s", str(d["ca_cert_hash"])))
	c.UI.Output(fmt.Sprintf("ca_not_after:      %s (%s)",
		time.Unix(caNotAfter, 0).UTC().Format(time.RFC3339),
		humanUntil(caNotAfter)))
	c.UI.Output(fmt.Sprintf("hub_endpoint:      %s", str(d["hub_endpoint"])))
	c.UI.Output(fmt.Sprintf("hub_cert_subject:  %s", str(d["hub_cert_subject"])))
	c.UI.Output(fmt.Sprintf("hub_cert_not_after: %s (%s)",
		time.Unix(hubNotAfter, 0).UTC().Format(time.RFC3339),
		humanUntil(hubNotAfter)))
	c.UI.Output(fmt.Sprintf("hub_dns_sans:      %s", strSlice(d["hub_dns_sans"])))
	c.UI.Output(fmt.Sprintf("hub_ip_sans:       %s", strSlice(d["hub_ip_sans"])))
	if listenerPort > 0 {
		c.UI.Output(fmt.Sprintf("listener_port:     %d (running)", listenerPort))
	} else {
		c.UI.Output("listener_port:     <not running>")
	}
	return 0
}

// --- bao relay ca rotate -----------------------------------------------------

type RelayCARotateCommand struct {
	*BaseCommand

	flagMount     string
	flagFull      bool
	flagDNSSANs   []string
	flagIPSANs    []string
	flagAssumeYes bool
}

var (
	_ cli.Command             = (*RelayCARotateCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayCARotateCommand)(nil)
)

func (c *RelayCARotateCommand) Synopsis() string { return "Rotate the hub TLS cert or the spoke-CA" }

func (c *RelayCARotateCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay ca rotate [options]

  Without -full: re-issues the hub TLS server cert from the existing CA.
    Transparent to spokes: their certs and the CA they trust do not change.
    Use this to renew an expiring hub cert or to add/replace SANs.

  With -full: regenerates the spoke-CA itself.
    DESTRUCTIVE. Every issued spoke client cert becomes invalid at the next
    TLS handshake; you must re-run 'bao relay init' (or just create a fresh
    bootstrap token with 'bao relay token create') and then 'bao relay join'
    on every spoke.

` + c.Flags().Help())
}

func (c *RelayCARotateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	f.BoolVar(&BoolVar{
		Name: "full", Target: &c.flagFull, Default: false,
		Usage: "Rotate the spoke-CA itself (destructive).",
	})
	f.StringSliceVar(&StringSliceVar{
		Name: "hub-dns-sans", Target: &c.flagDNSSANs,
		Default: nil, Usage: "Override DNS SANs on the new hub cert.",
	})
	f.StringSliceVar(&StringSliceVar{
		Name: "hub-ip-sans", Target: &c.flagIPSANs,
		Default: nil, Usage: "Override IP SANs on the new hub cert.",
	})
	f.BoolVar(&BoolVar{
		Name: "yes", Target: &c.flagAssumeYes, Default: false,
		Usage: "Skip the confirmation prompt for -full.",
	})
	return set
}

func (c *RelayCARotateCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayCARotateCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayCARotateCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.flagFull && !c.flagAssumeYes {
		c.UI.Error("Refusing to perform a full CA rotation without -yes.")
		c.UI.Error("Every spoke will need to re-join. Re-run with -yes if you are sure.")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	body := map[string]interface{}{"full": c.flagFull}
	if len(c.flagDNSSANs) > 0 {
		body["hub_dns_sans"] = c.flagDNSSANs
	}
	if len(c.flagIPSANs) > 0 {
		body["hub_ip_sans"] = c.flagIPSANs
	}
	resp, err := client.Logical().Write(strings.Trim(c.flagMount, "/")+"/ca/rotate", body)
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	if resp == nil {
		c.UI.Error("rotate returned no data")
		return 2
	}
	c.UI.Output(fmt.Sprintf("Rotated:       %s", str(resp.Data["rotated"])))
	c.UI.Output(fmt.Sprintf("New CA hash:   %s", str(resp.Data["ca_cert_hash"])))
	for _, w := range resp.Warnings {
		c.UI.Warn("WARNING: " + w)
	}
	return 0
}

// --- shared formatting helpers ----------------------------------------------

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strSlice(v interface{}) string {
	arr, ok := v.([]interface{})
	if !ok {
		return "-"
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

// humanUntil returns a short relative description of a Unix time vs. now:
// "in 11d", "expired 3d ago", or "" for zero timestamps.
func humanUntil(unix int64) string {
	if unix == 0 {
		return "never"
	}
	d := time.Until(time.Unix(unix, 0))
	if d < 0 {
		return fmt.Sprintf("expired %s ago", roundDur(-d))
	}
	return fmt.Sprintf("in %s", roundDur(d))
}

func roundDur(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
}
