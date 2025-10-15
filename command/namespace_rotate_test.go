// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"testing"

	"github.com/hashicorp/cli"
	"github.com/stretchr/testify/require"
)

func testNamespaceRotateCommand(tb testing.TB) (*cli.MockUi, *NamespaceRotateCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceRotateCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceRotateCommand_Run(t *testing.T) {
	t.Parallel()
	nsName := "ns"

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"too_many_args",
			[]string{"foo", "bar"},
			"Too many arguments",
			1,
		},
		{
			"not_enough_args",
			[]string{},
			"Not enough arguments",
			1,
		},
		{
			"no_namespace_existing",
			[]string{"unknown"},
			"doesn't exist",
			2,
		},
		{
			"happy path",
			[]string{"ns"},
			"Success! Rotated encryption key",
			0,
		},
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, _, closer := testVaultServerWithNamespace(t, nsName, false)
				defer closer()

				ui, cmd := testNamespaceRotateCommand(t)
				cmd.client = client

				code := cmd.Run(tc.args)
				require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

				combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
				require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)

				if code == 0 {
					status, err := client.Sys().NamespaceKeyStatus(nsName)
					require.NoError(t, err)
					require.Greater(t, status.Term, 1)
				}
			})
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceRotateCommand(t)
		assertNoTabs(t, cmd)
	})
}
