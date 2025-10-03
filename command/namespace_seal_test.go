// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"testing"

	"github.com/hashicorp/cli"
	"github.com/stretchr/testify/require"
)

func testNamespaceSealCommand(tb testing.TB) (*cli.MockUi, *NamespaceSealCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceSealCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceSealCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		args   []string
		out    string
		code   int
		sealed bool
	}{
		{
			name:   "not enough arguments provided",
			args:   []string{},
			out:    "Not enough arguments",
			code:   1,
			sealed: false,
		},
		{
			name:   "too many arguments provided",
			args:   []string{"foo", "bar"},
			out:    "Too many arguments",
			code:   1,
			sealed: false,
		},
		{
			name:   "happy path",
			args:   []string{"ns1"},
			out:    `Success! Namespace "ns1" is sealed.`,
			code:   0,
			sealed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsName := "ns1"
			client, _, closer := testVaultServerWithNamespace(t, nsName, false)
			defer closer()

			ui, cmd := testNamespaceSealCommand(t)
			cmd.client = client

			code := cmd.Run(tc.args)
			require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

			combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
			require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)

			sealStatus, err := client.Sys().NamespaceSealStatus(nsName)
			require.NoError(t, err)
			require.Equal(t, tc.sealed, sealStatus.Sealed)
		})
	}

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceSealCommand(t)
		assertNoTabs(t, cmd)
	})
}
