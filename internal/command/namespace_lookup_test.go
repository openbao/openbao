// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"
	"testing"

	"github.com/hashicorp/cli"
)

func testNamespaceLookupCommand(tb testing.TB) (*cli.MockUi, *NamespaceLookupCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceLookupCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceLookupCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"not_enough_args",
			[]string{},
			"Not enough arguments",
			1,
		},
		{
			"too_many_args",
			[]string{"foo", "bar"},
			"Too many arguments",
			1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, closer := testVaultServer(t)
			defer closer()

			ui, cmd := testNamespaceLookupCommand(t)
			cmd.client = client

			code := cmd.Run(tc.args)
			if code != tc.code {
				t.Errorf("expected %d to be %d", code, tc.code)
			}

			combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
			if !strings.Contains(combined, tc.out) {
				t.Errorf("expected %q to contain %q", combined, tc.out)
			}
		})
	}

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceLookupCommand(t)
		assertNoTabs(t, cmd)
	})
}
