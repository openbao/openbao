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

// RelayListCommand prints the spokes currently connected to the hub's gRPC
// proxy server. This is the operator's "what's running" view.
type RelayListCommand struct {
	*BaseCommand

	flagMount string
}

var (
	_ cli.Command             = (*RelayListCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayListCommand)(nil)
)

func (c *RelayListCommand) Synopsis() string {
	return "List spokes currently connected to the hub"
}

func (c *RelayListCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay list [options]

  Lists spokes that have an active Connect stream to the hub's proxy gRPC
  server. The view is point-in-time and may race with a disconnect.

` + c.Flags().Help())
}

func (c *RelayListCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&StringVar{
		Name: "mount", Target: &c.flagMount, Default: "relay",
		Usage: "Mount path of the relay backend.",
	})
	return set
}

func (c *RelayListCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayListCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayListCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	resp, err := client.Logical().Read(strings.Trim(c.flagMount, "/") + "/spokes")
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	if resp == nil || resp.Data == nil {
		c.UI.Output("(no data)")
		return 0
	}

	port := asUnix(resp.Data["listener_port"])
	if port == 0 {
		c.UI.Output("Proxy gRPC listener is not running.")
		c.UI.Output("Run `bao relay init` on the hub before any spokes can connect.")
		return 0
	}
	c.UI.Output(fmt.Sprintf("Listener: :%d", port))

	count := asUnix(resp.Data["connected_count"])
	healthy := asUnix(resp.Data["healthy_count"])
	stale := asUnix(resp.Data["stale_after_seconds"])
	c.UI.Output(fmt.Sprintf("Connected: %d total, %d healthy (stale after %ds)",
		count, healthy, stale))

	if count == 0 {
		return 0
	}

	rawSpokes, _ := resp.Data["spokes"].([]interface{})
	c.UI.Output("")
	c.UI.Output(fmt.Sprintf("%-20s  %-10s  %-9s  %-10s  %s", "NAME", "LAST SEEN", "UPTIME", "CERT EXP", "HEALTH"))
	for _, s := range rawSpokes {
		m, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		name := str(m["name"])
		lastSeenSecs := asUnix(m["last_seen_seconds"])
		connectedAt := asUnix(m["connected_at_unix"])
		certNotAfter := asUnix(m["cert_not_after"])
		health, _ := m["healthy"].(bool)
		healthStr := "OK"
		if !health {
			healthStr = "STALE"
		}
		uptime := "-"
		if connectedAt > 0 {
			uptime = shortDuration(time.Since(time.Unix(connectedAt, 0)))
		}
		// Cert expiry as a relative duration ("12d", "expired", or "-" when
		// the hub never captured the spoke's client cert).
		certExp := "-"
		if certNotAfter > 0 {
			if d := time.Until(time.Unix(certNotAfter, 0)); d > 0 {
				certExp = shortDuration(d)
			} else {
				certExp = "expired"
			}
		}
		// Guard against future timestamps: a clock skew (or a NTP step
		// between the hub computing now-lastSeen and the CLI rendering it)
		// can briefly produce a negative value, which would render as
		// "-3s ago" and looks broken. Clamp to "0s ago" in that case.
		if lastSeenSecs < 0 {
			lastSeenSecs = 0
		}
		c.UI.Output(fmt.Sprintf("%-20s  %-10s  %-9s  %-10s  %s",
			name,
			fmt.Sprintf("%ds ago", lastSeenSecs),
			uptime,
			certExp,
			healthStr))
	}
	return 0
}

// shortDuration prints a duration as the largest single unit (e.g. "3d",
// "47m", "12s") for the relay list view. The package's humanDuration formats
// differently and isn't quite what we want here.
func shortDuration(d time.Duration) string {
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
