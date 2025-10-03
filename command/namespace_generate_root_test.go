// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"encoding/base64"
	"io"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/sdk/v2/helper/xor"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func testNamespaceGenerateRootCommand(tb testing.TB) (*cli.MockUi, *NamespaceGenerateRootCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceGenerateRootCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceGenerateRootCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"init_invalid_otp",
			[]string{
				"-init",
				"-otp", "not-a-valid-otp",
			},
			"OTP string is wrong length",
			2,
		},
		{
			"init_pgp_multi",
			[]string{
				"-init",
				"-pgp-key", "keybase:hashicorp",
				"-pgp-key", "keybase:jefferai",
			},
			"can only be specified once",
			1,
		},
		{
			"init_pgp_multi_inline",
			[]string{
				"-init",
				"-pgp-key", "keybase:hashicorp,keybase:jefferai",
			},
			"can only specify one pgp key",
			1,
		},
		{
			"init_pgp_otp",
			[]string{
				"-init",
				"-pgp-key", "keybase:hashicorp",
				"-otp", "abcd1234",
			},
			"cannot specify both -otp and -pgp-key",
			1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsName := "ns1"
			client, _, closer := testVaultServerWithNamespace(t, nsName, false)
			defer closer()

			ui, cmd := testNamespaceGenerateRootCommand(t)
			cmd.client = client

			code := cmd.Run(append(tc.args, "ns1"))
			require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

			combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
			require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)
		})
	}

	t.Run("generate_otp", func(t *testing.T) {
		nsName := "ns2"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		_, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client
		code := cmd.Run([]string{
			"-generate-otp",
			"ns2",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)
	})

	t.Run("decode", func(t *testing.T) {
		encoded := "R3kcBAYdDgc0Y2p0AiUSAlUkN1wlIxczGSBWIlgjMwMg"
		otp := "4WuTpwCSNW01rGYWghYoGDeaqpxWodpJq"

		nsName := "ns3"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client

		// Simulate piped output to print raw output
		old := os.Stdout
		_, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w

		code := cmd.Run([]string{
			"-decode", encoded,
			"-otp", otp,
			"ns3",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		_ = w.Close()
		os.Stdout = old

		expected := "s.iPvjMTz4ZEpbKU2Ln3bgrRhP.u7GCIQ"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)
	})

	t.Run("decode_from_stdin", func(t *testing.T) {
		encoded := "R3kcBAYdDgc0Y2p0AiUSAlUkN1wlIxczGSBWIlgjMwMg"
		otp := "4WuTpwCSNW01rGYWghYoGDeaqpxWodpJq"

		nsName := "ns4"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		stdinR, stdinW := io.Pipe()
		go func() {
			_, err := stdinW.Write([]byte(encoded))
			require.NoError(t, err)
			err = stdinW.Close()
			require.NoError(t, err)
		}()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		// Simulate piped output to print raw output
		old := os.Stdout
		_, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w

		code := cmd.Run([]string{
			"-decode", "-", // read from stdin
			"-otp", otp,
			"ns4",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		_ = w.Close()
		os.Stdout = old

		expected := "s.iPvjMTz4ZEpbKU2Ln3bgrRhP.u7GCIQ"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)
	})

	t.Run("decode_from_stdin_empty", func(t *testing.T) {
		encoded := ""
		otp := "4WuTpwCSNW01rGYWghYoGDeaqpxWodpJq"

		nsName := "ns5"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		stdinR, stdinW := io.Pipe()
		go func() {
			_, err := stdinW.Write([]byte(encoded))
			require.NoError(t, err)
			err = stdinW.Close()
			require.NoError(t, err)
		}()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		// Simulate piped output to print raw output
		old := os.Stdout
		_, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w

		code := cmd.Run([]string{
			"-decode", "-", // read from stdin
			"-otp", otp,
			"ns5",
		})
		require.Equalf(t, 1, code, "expected %d to be 1", code)

		_ = w.Close()
		os.Stdout = old

		expected := "Missing encoded value"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)
	})

	t.Run("cancel", func(t *testing.T) {
		nsName := "ns6"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize a generation
		_, err := client.Sys().NamespaceGenerateRootInit("", "", nsName)
		require.NoError(t, err)

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-cancel",
			"ns6",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		expected := "Cancelled any ongoing root token generation operations for namespace"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)

		status, err := client.Sys().NamespaceGenerateRootStatus(nsName)
		require.NoError(t, err)
		require.False(t, status.Started)
	})

	t.Run("init_otp", func(t *testing.T) {
		nsName := "ns7"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"ns7",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		expected := "Nonce"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)

		status, err := client.Sys().NamespaceGenerateRootStatus(nsName)
		require.NoError(t, err)
		require.True(t, status.Started)
	})

	t.Run("init_pgp", func(t *testing.T) {
		pgpKey := "keybase:hashicorp"
		pgpFingerprint := "c874011f0ab405110d02105534365d9472d7468f"

		nsName := "ns8"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-pgp-key", pgpKey,
			"ns8",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		expected := "Nonce"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)

		status, err := client.Sys().NamespaceGenerateRootStatus(nsName)
		require.NoError(t, err)
		require.True(t, status.Started)
		require.Equal(t, pgpFingerprint, status.PGPFingerprint)
	})

	t.Run("status", func(t *testing.T) {
		nsName := "ns9"
		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-status",
			"ns9",
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		expected := "Nonce"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Containsf(t, combined, expected, "expected %q to contain %q", combined, expected)
	})

	t.Run("provide_arg", func(t *testing.T) {
		nsName := "ns10"
		client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize a generation
		status, err := client.Sys().NamespaceGenerateRootInit("", "", nsName)
		require.NoError(t, err)

		nonce := status.Nonce
		otp := status.OTP

		// Supply the n-1 unseal keys
		var ui *cli.MockUi
		var cmd *NamespaceGenerateRootCommand
		for i := range status.Required {
			ui, cmd = testNamespaceGenerateRootCommand(t)
			cmd.client = client

			code := cmd.Run([]string{
				"-nonce", nonce,
				nsName,
				unsealShares[i],
			})
			require.Equalf(t, 0, code, "expected %d to be 0", code)
		}

		reToken := regexp.MustCompile(`Encoded Token\s+(.+)`)
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		match := reToken.FindAllStringSubmatch(combined, -1)
		if len(match) < 1 || len(match[0]) < 2 {
			t.Fatalf("no match: %#v", match)
		}

		tokenBytes, err := base64.RawStdEncoding.DecodeString(match[0][1])
		require.NoError(t, err)

		token, err := xor.XORBytes(tokenBytes, []byte(otp))
		require.NoError(t, err)

		if l, exp := len(token), vault.NSTokenLength+vault.TokenPrefixLength; l != exp {
			t.Errorf("expected %d to be %d: %s", l, exp, token)
		}
	})

	t.Run("provide_stdin", func(t *testing.T) {
		nsName := "ns11"
		client, unsealShares, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize a generation
		status, err := client.Sys().NamespaceGenerateRootInit("", "", nsName)
		require.NoError(t, err)

		nonce := status.Nonce
		otp := status.OTP

		stdinR, stdinW := io.Pipe()
		go func() {
			_, err := stdinW.Write([]byte(unsealShares[0]))
			require.NoError(t, err)
			err = stdinW.Close()
			require.NoError(t, err)
		}()

		_, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code := cmd.Run([]string{
			"-nonce", nonce,
			nsName,
			"-", // read from stdin
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		stdinR, stdinW = io.Pipe()
		go func() {
			_, err := stdinW.Write([]byte(unsealShares[1])) // the last unseal key
			require.NoError(t, err)
			err = stdinW.Close()
			require.NoError(t, err)
		}()

		ui, cmd := testNamespaceGenerateRootCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code = cmd.Run([]string{
			"-nonce", nonce,
			nsName,
			"-", // read from stdin
		})
		require.Equalf(t, 0, code, "expected %d to be 0", code)

		reToken := regexp.MustCompile(`Encoded Token\s+(.+)`)
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		match := reToken.FindAllStringSubmatch(combined, -1)
		if len(match) < 1 || len(match[0]) < 2 {
			t.Fatalf("no match: %#v", match)
		}

		tokenBytes, err := base64.RawStdEncoding.DecodeString(match[0][1])
		require.NoError(t, err)

		token, err := xor.XORBytes(tokenBytes, []byte(otp))
		require.NoError(t, err)

		if l, exp := len(token), vault.NSTokenLength+vault.TokenPrefixLength; l != exp {
			t.Errorf("expected %d to be %d: %s", l, exp, token)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceGenerateRootCommand(t)
		assertNoTabs(t, cmd)
	})
}
