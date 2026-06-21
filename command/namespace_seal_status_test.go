// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"io"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/stretchr/testify/require"
)

func testNamespaceSealStatusCommand(tb testing.TB) (*cli.MockUi, *NamespaceSealStatusCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceSealStatusCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceSealStatusCommand_Run(t *testing.T) {
	t.Parallel()
	nsName := "ns"

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			name: "not enough arguments provided",
			args: []string{},
			out:  "Not enough arguments",
			code: 1,
		},
		{
			name: "too many arguments provided",
			args: []string{"foo", "bar", "baz"},
			out:  "Too many arguments",
			code: 1,
		},
	}
	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, _, closer := testVaultServerWithNamespace(t, nsName, true)
				defer closer()

				ui, cmd := testNamespaceSealStatusCommand(t)
				cmd.client = client

				code := cmd.Run(tc.args)
				require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

				combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
				require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)
			})
		}
	})

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, true)
		defer closer()

		ui, cmd := testNamespaceSealStatusCommand(t)
		cmd.client = client

		// Reset and check output
		code := cmd.Run([]string{nsName})
		require.Equalf(t, 0, code, "expected %d to be 0: %s", code, ui.ErrorWriter.String())

		for _, key := range unsealShares {
			ui, cmd := testNamespaceUnsealCommand(t)
			cmd.client = client
			cmd.testOutput = io.Discard

			// Reset and check output
			code := cmd.Run([]string{nsName, key})
			require.Equalf(t, 0, code, "expected %d to be 0: %s", code, ui.ErrorWriter.String())
		}

		ui, cmd = testNamespaceSealStatusCommand(t)
		cmd.client = client

		// Reset and check output
		code = cmd.Run([]string{nsName})
		require.Equalf(t, 0, code, "expected %d to be 0: %s", code, ui.ErrorWriter.String())
	})
}
