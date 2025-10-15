// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !race

package command

import (
	"io"
	"regexp"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cli"
)

func testNamespaceRotateKeysCommand(tb testing.TB) (*cli.MockUi, *NamespaceRotateKeysCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &NamespaceRotateKeysCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestNamespaceRotateKeysCommand_Run(t *testing.T) {
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
			[]string{"foo", "bar", "baz"},
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
			"pgp_keys_multi",
			[]string{
				"-init",
				"-pgp-keys", "keybase:hashicorp",
				"-pgp-keys", "keybase:jefferai",
				nsName,
			},
			"can only be specified once",
			1,
		},
		{
			"key_shares_pgp_less",
			[]string{
				"-init",
				"-key-shares", "10",
				"-pgp-keys", "keybase:jefferai,keybase:sethvargo",
				nsName,
			},
			"count mismatch",
			2,
		},
		{
			"key_shares_pgp_more",
			[]string{
				"-init",
				"-key-shares", "1",
				"-key-threshold", "1",
				"-pgp-keys", "keybase:jefferai,keybase:sethvargo",
				nsName,
			},
			"count mismatch",
			2,
		},
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, _, closer := testVaultServerWithNamespace(t, nsName, false)
				defer closer()

				ui, cmd := testNamespaceRotateKeysCommand(t)
				cmd.client = client

				code := cmd.Run(tc.args)
				require.Equalf(t, tc.code, code, "expected %d to be %d", code, tc.code)

				combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
				require.Containsf(t, combined, tc.out, "expected %q to contain %q", combined, tc.out)
			})
		}
	})

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		// Verify the non-init response
		code := cmd.Run([]string{
			"-status",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		// Now init to verify the init response
		_, err := client.Sys().NamespaceRotateRootInit(nsName,
			&api.RotateInitRequest{
				SecretShares:    1,
				SecretThreshold: 1,
			})
		require.NoError(t, err)

		// Verify the init response
		ui, cmd = testNamespaceRotateKeysCommand(t)
		cmd.client = client
		code = cmd.Run([]string{
			"-status",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined = ui.OutputWriter.String()
		require.Contains(t, combined, "Progress")
	})

	t.Run("cancel", func(t *testing.T) {
		t.Parallel()

		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize rotation
		_, err := client.Sys().NamespaceRotateRootInit(nsName,
			&api.RotateInitRequest{
				SecretShares:    1,
				SecretThreshold: 1,
			})
		require.NoError(t, err)

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-cancel",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Contains(t, combined, "Success! Canceled rotation")

		status, err := client.Sys().NamespaceGenerateRootStatus(nsName)
		require.NoError(t, err)
		require.False(t, status.Started)
	})

	t.Run("init", func(t *testing.T) {
		t.Parallel()

		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
			nsName,
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d: %s", code, exp, ui.ErrorWriter.String())
		}

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		status, err := client.Sys().NamespaceRotateRootStatus(nsName)
		require.NoError(t, err)
		require.True(t, status.Started)
	})

	t.Run("init_pgp", func(t *testing.T) {
		t.Parallel()

		pgpKey := "keybase:hashicorp"
		pgpFingerprints := []string{"c874011f0ab405110d02105534365d9472d7468f"}

		client, _, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
			"-pgp-keys", pgpKey,
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		status, err := client.Sys().NamespaceRotateRootStatus(nsName)
		require.NoError(t, err)
		require.True(t, status.Started)
		require.ElementsMatch(t, status.PGPFingerprints, pgpFingerprints)
	})

	t.Run("provide_arg", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().NamespaceRotateRootInit(nsName,
			&api.RotateInitRequest{
				SecretShares:    1,
				SecretThreshold: 1,
			})
		require.NoError(t, err)
		nonce := status.Nonce

		// Supply the first n-1 unseal keys
		for _, key := range keys[:len(keys)-1] {
			ui, cmd := testNamespaceRotateKeysCommand(t)
			cmd.client = client
			code := cmd.Run([]string{
				"-nonce", nonce,
				nsName,
				key,
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())
		}

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-nonce", nonce,
			nsName,
			keys[len(keys)-1], // the last unseal key
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		// Grab the unseal key and try to unseal
		unsealKey := match[0][1]
		err = client.Sys().SealNamespace(nsName)
		require.NoError(t, err)

		sealStatus, err := client.Sys().UnsealNamespace(
			&api.UnsealNamespaceRequest{
				Name: nsName,
				Key:  unsealKey,
			})
		require.NoError(t, err)
		require.False(t, sealStatus.Sealed)
	})

	t.Run("provide_stdin", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().NamespaceRotateRootInit(nsName,
			&api.RotateInitRequest{
				SecretShares:    1,
				SecretThreshold: 1,
			})
		require.NoError(t, err)
		nonce := status.Nonce

		// Supply the first n-1 unseal keys
		for _, key := range keys[:len(keys)-1] {
			stdinR, stdinW := io.Pipe()
			go func() {
				_, err := stdinW.Write([]byte(key))
				require.NoError(t, err)

				err = stdinW.Close()
				require.NoError(t, err)
			}()

			ui, cmd := testNamespaceRotateKeysCommand(t)
			cmd.client = client
			cmd.testStdin = stdinR

			code := cmd.Run([]string{
				"-nonce", nonce,
				nsName,
				"-",
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())
		}

		stdinR, stdinW := io.Pipe()
		go func() {
			_, err := stdinW.Write([]byte(keys[len(keys)-1])) // the last unseal key
			require.NoError(t, err)

			err = stdinW.Close()
			require.NoError(t, err)
		}()

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code := cmd.Run([]string{
			"-nonce", nonce,
			nsName,
			"-",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		// Grab the unseal key and try to unseal
		unsealKey := match[0][1]
		err = client.Sys().SealNamespace(nsName)
		require.NoError(t, err)

		sealStatus, err := client.Sys().UnsealNamespace(
			&api.UnsealNamespaceRequest{
				Name: nsName,
				Key:  unsealKey,
			})
		require.NoError(t, err)
		require.False(t, sealStatus.Sealed)
	})

	t.Run("backup", func(t *testing.T) {
		t.Parallel()

		pgpKey := "keybase:hashicorp"
		client, keys, closer := testVaultServerWithNamespace(t, nsName, false)
		defer closer()

		ui, cmd := testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
			"-pgp-keys", pgpKey,
			"-backup",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		// Get the status for the nonce
		status, err := client.Sys().NamespaceRotateRootStatus(nsName)
		require.NoError(t, err)
		nonce := status.Nonce

		var combined string
		// Supply the unseal keys
		for _, key := range keys {
			ui, cmd := testNamespaceRotateKeysCommand(t)
			cmd.client = client

			code := cmd.Run([]string{
				"-nonce", nonce,
				nsName,
				key,
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

			// Append to our output string
			combined += ui.OutputWriter.String()
		}

		re := regexp.MustCompile(`Key 1 fingerprint: (.+); value: (.+)`)
		match := re.FindAllStringSubmatch(combined, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 3)

		// Grab the output fingerprint and encrypted key
		fingerprint, encryptedKey := match[0][1], match[0][2]

		// Get the backup
		ui, cmd = testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code = cmd.Run([]string{
			"-backup-retrieve",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(t, output, fingerprint)
		require.Contains(t, output, encryptedKey)

		// Delete the backup
		ui, cmd = testNamespaceRotateKeysCommand(t)
		cmd.client = client

		code = cmd.Run([]string{
			"-backup-delete",
			nsName,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		_, err = client.Sys().NamespaceRotateRootRetrieveBackup(nsName)
		require.Error(t, err)
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testNamespaceRotateKeysCommand(t)
		assertNoTabs(t, cmd)
	})
}
