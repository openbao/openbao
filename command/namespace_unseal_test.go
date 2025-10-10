// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

func testNamespaceUnsealCommand(tb testing.TB) (*cli.MockUi, *NamespaceUnsealCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceUnsealCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceUnsealCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		args   []string
		out    string
		code   int
		sealed bool
	}{
		{
			name:   "not interactive terminal refuse",
			args:   []string{"-non-interactive", "test"},
			out:    "Refusing to read from stdin",
			code:   1,
			sealed: true,
		},
		{
			name:   "not enough arguments provided",
			args:   []string{},
			out:    "Not enough arguments",
			code:   1,
			sealed: true,
		},
		{
			name:   "too many arguments provided",
			args:   []string{"foo", "bar", "baz"},
			out:    "Too many arguments",
			code:   1,
			sealed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsName := "ns1"
			client, _, closer := testVaultServerWithNamespace(t, nsName, true)
			defer closer()

			ui, cmd := testNamespaceUnsealCommand(t)
			cmd.client = client
			cmd.testOutput = io.Discard

			code := cmd.Run(tc.args)
			require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

			combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
			require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)

			sealStatus, err := client.Sys().NamespaceSealStatus(nsName)
			require.NoError(t, err)
			require.Equal(t, tc.sealed, sealStatus.Sealed)
		})
	}

	t.Run("reset flag", func(t *testing.T) {
		nsName := "ns2"
		client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, true)
		defer closer()

		// Enter an unseal key
		status, err := client.Sys().UnsealNamespace(&api.UnsealNamespaceRequest{Name: nsName, Key: unsealShares[0]})
		require.NoError(t, err)
		require.Equal(t, 1, status.Progress)

		ui, cmd := testNamespaceUnsealCommand(t)
		cmd.client = client
		cmd.testOutput = io.Discard

		// Reset and check output
		code := cmd.Run([]string{"-reset", "ns2"})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		expected := "0/2"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)

		sealStatus, err := client.Sys().NamespaceSealStatus(nsName)
		require.NoError(t, err)
		require.Equal(t, true, sealStatus.Sealed)
	})

	t.Run("happy path", func(t *testing.T) {
		nsName := "ns3"
		client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, true)
		defer closer()

		for _, key := range unsealShares {
			ui, cmd := testNamespaceUnsealCommand(t)
			cmd.client = client
			cmd.testOutput = io.Discard

			// Reset and check output
			code := cmd.Run([]string{"ns3", key})
			require.Equalf(t, 0, code, "expected %d to be 0: %s", code, ui.ErrorWriter.String())
		}

		sealStatus, err := client.Sys().NamespaceSealStatus(nsName)
		require.NoError(t, err)
		require.Equal(t, false, sealStatus.Sealed)
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceUnsealCommand(t)
		assertNoTabs(t, cmd)
	})
}

func TestNamespaceUnsealCommand_Format(t *testing.T) {
	defer func() {
		require.NoError(t, os.Setenv(EnvVaultCLINoColor, ""))
	}()

	nsName := "ns"
	client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, true)
	defer closer()

	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	runOpts := &RunOptions{
		Stdout: stdout,
		Stderr: stderr,
		Client: client,
	}

	args, format, _, _, _ := setupEnv([]string{"namespace", "unseal", "-format", "json", "ns"})
	require.Equal(t, "json", format)

	// Unseal with one key
	code := RunCustom(append(args, []string{unsealShares[0]}...), runOpts)
	require.Equalf(t, 0, code, "expected %d to be 0: %s", code, stderr.String())
	require.True(t, json.Valid(stdout.Bytes()), "expected output to be valid JSON")
}
