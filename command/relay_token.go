// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

// asUnix coerces a JSON-decoded number (json.Number, float64, or int) to a
// Unix timestamp. The Vault API client decodes JSON numbers as json.Number to
// avoid float precision loss, so the more obvious float64 assertion silently
// returns 0 for every numeric field.
func asUnix(v interface{}) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// --- bao relay token (parent) -----------------------------------------------

type RelayTokenCommand struct {
	*BaseCommand
}

var _ cli.Command = (*RelayTokenCommand)(nil)

func (c *RelayTokenCommand) Synopsis() string {
	return "Manage bootstrap tokens for spoke joins"
}

func (c *RelayTokenCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay token <subcommand> [options]

  Manage bootstrap tokens stored at the relay/ backend.

Subcommands:
  create   Create a bootstrap token
  list     List outstanding bootstrap tokens
  revoke   Revoke a bootstrap token

`)
}

func (c *RelayTokenCommand) Run(args []string) int {
	return cli.RunResultHelp
}

// --- bao relay token create -------------------------------------------------

type RelayTokenCreateCommand struct {
	*BaseCommand

	flagMount        string
	flagTTL          string
	flagAllowedSpoke string
	flagDescription  string
}

var (
	_ cli.Command             = (*RelayTokenCreateCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayTokenCreateCommand)(nil)
)

func (c *RelayTokenCreateCommand) Synopsis() string { return "Create a bootstrap token" }
func (c *RelayTokenCreateCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay token create [options]

  Creates a bootstrap token at the relay/ backend and prints it. The token is
  shown only once.

` + c.Flags().Help())
}

func (c *RelayTokenCreateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	f.StringVar(&StringVar{
		Name: "ttl", Target: &c.flagTTL, Default: "24h",
		Usage: "Token lifetime; 0 disables expiry.",
	})
	f.StringVar(&StringVar{
		Name: "allowed-spoke-name", Target: &c.flagAllowedSpoke,
		Default: "",
		Usage: "Restrict the token to a specific spoke identity. " +
			"Empty (default) means any spoke name may join with this token. " +
			"Spoke names are case-sensitive (lowercase by convention).",
	})
	f.StringVar(&StringVar{
		Name: "description", Target: &c.flagDescription,
		Default: "", Usage: "Free-form description recorded with the token.",
	})
	return set
}

func (c *RelayTokenCreateCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayTokenCreateCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayTokenCreateCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	mount := strings.Trim(c.flagMount, "/")
	body := map[string]interface{}{
		"ttl":         c.flagTTL,
		"description": c.flagDescription,
	}
	if c.flagAllowedSpoke != "" {
		body["allowed_spoke_name"] = c.flagAllowedSpoke
	}
	resp, err := client.Logical().Write(mount+"/bootstrap-tokens", body)
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	tok, _ := resp.Data["token"].(string)
	id, _ := resp.Data["id"].(string)
	exp := asUnix(resp.Data["expiration_unix"])

	// Warn on stderr BEFORE the token so an operator scrolling shell history
	// or a pipeline grepping for "token:" still sees the secrecy notice.
	// The backend also attaches a Warning to the response; surface that too
	// in case a future backend message diverges.
	c.UI.Warn("This token is shown ONCE. Copy it now — it cannot be retrieved later.")
	c.UI.Warn("Treat it as a credential: do not paste into logs, chat, or audit-forwarded transcripts.")
	for _, w := range resp.Warnings {
		c.UI.Warn(w)
	}
	c.UI.Output(fmt.Sprintf("token:           %s", tok))
	c.UI.Output(fmt.Sprintf("id:              %s", id))
	if exp > 0 {
		c.UI.Output(fmt.Sprintf("expiration:      %s", time.Unix(exp, 0).UTC().Format(time.RFC3339)))
	} else {
		c.UI.Output("expiration:      never")
	}
	if c.flagAllowedSpoke != "" {
		c.UI.Output(fmt.Sprintf("allowed_spoke:   %s", c.flagAllowedSpoke))
	}
	return 0
}

// --- bao relay token list ---------------------------------------------------

type RelayTokenListCommand struct {
	*BaseCommand

	flagMount string
}

var (
	_ cli.Command             = (*RelayTokenListCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayTokenListCommand)(nil)
)

func (c *RelayTokenListCommand) Synopsis() string { return "List bootstrap tokens" }
func (c *RelayTokenListCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay token list [options]

  Lists outstanding bootstrap token ids and their metadata.

` + c.Flags().Help())
}

func (c *RelayTokenListCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	return set
}

func (c *RelayTokenListCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayTokenListCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayTokenListCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	mount := strings.Trim(c.flagMount, "/")
	resp, err := client.Logical().List(mount + "/bootstrap-tokens")
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	if resp == nil || resp.Data == nil {
		c.UI.Output("No tokens.")
		return 0
	}
	keysRaw, _ := resp.Data["keys"].([]interface{})
	ids := make([]string, 0, len(keysRaw))
	for _, k := range keysRaw {
		if s, ok := k.(string); ok {
			ids = append(ids, s)
		}
	}
	sort.Strings(ids)

	c.UI.Output(fmt.Sprintf("%-8s  %-20s  %-7s  %s", "ID", "EXPIRES", "EXPIRED", "DESCRIPTION"))
	for _, id := range ids {
		tr, err := client.Logical().Read(mount + "/bootstrap-tokens/" + id)
		if err != nil || tr == nil {
			c.UI.Output(fmt.Sprintf("%-8s  <read error>", id))
			continue
		}
		exp := asUnix(tr.Data["expiration_unix"])
		expStr := "never"
		if exp > 0 {
			expStr = time.Unix(exp, 0).UTC().Format(time.RFC3339)
		}
		expired, _ := tr.Data["expired"].(bool)
		desc, _ := tr.Data["description"].(string)
		c.UI.Output(fmt.Sprintf("%-8s  %-20s  %-7v  %s", id, expStr, expired, desc))
	}
	return 0
}

// --- bao relay token revoke -------------------------------------------------

type RelayTokenRevokeCommand struct {
	*BaseCommand

	flagMount string
}

var (
	_ cli.Command             = (*RelayTokenRevokeCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayTokenRevokeCommand)(nil)
)

func (c *RelayTokenRevokeCommand) Synopsis() string { return "Revoke a bootstrap token by id" }
func (c *RelayTokenRevokeCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay token revoke [options] TOKEN_ID

  Revokes a bootstrap token. TOKEN_ID is the 6-character id printed by
  'bao relay token create' (the part before the dot).

` + c.Flags().Help())
}

func (c *RelayTokenRevokeCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	return set
}

func (c *RelayTokenRevokeCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayTokenRevokeCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayTokenRevokeCommand) Run(args []string) int {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	rest := f.Args()
	if len(rest) != 1 {
		c.UI.Error("Usage: bao relay token revoke TOKEN_ID")
		return 1
	}
	id := rest[0]
	if idx := strings.Index(id, "."); idx >= 0 {
		id = id[:idx] // accept either "id" or full "id.secret"
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	mount := strings.Trim(c.flagMount, "/")
	if _, err := client.Logical().Delete(mount + "/bootstrap-tokens/" + id); err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	c.UI.Output(fmt.Sprintf("Revoked %s.", id))
	return 0
}
