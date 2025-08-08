// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !race

package command

import (
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/roottoken"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
)

func testOperatorRotateKeysCommand(tb testing.TB) (*cli.MockUi, *OperatorRotateKeysCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &OperatorRotateKeysCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestOperatorRotateKeysCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"pgp_keys_multi",
			[]string{
				"-init",
				"-pgp-keys", "keybase:hashicorp",
				"-pgp-keys", "keybase:jefferai",
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

				client, closer := testVaultServer(t)
				defer closer()

				ui, cmd := testOperatorRotateKeysCommand(t)
				cmd.client = client

				code := cmd.Run(tc.args)
				require.Equal(t, tc.code, code)
				combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
				require.Contains(t, combined, tc.out)
			})
		}
	})

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		// Verify the non-init response
		code := cmd.Run([]string{
			"-status",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		// Now init to verify the init response
		_, err := client.Sys().RotateRootInit(&api.RotateInitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		})
		require.NoError(t, err)

		// Verify the init response
		ui, cmd = testOperatorRotateKeysCommand(t)
		cmd.client = client
		code = cmd.Run([]string{
			"-status",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined = ui.OutputWriter.String()
		require.Contains(t, combined, "Progress")
	})

	t.Run("cancel", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		// Initialize rotation
		_, err := client.Sys().RotateRootInit(&api.RotateInitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		})
		require.NoError(t, err)

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-cancel",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Contains(t, combined, "Success! Canceled rotation")

		status, err := client.Sys().GenerateRootStatus()
		require.NoError(t, err)
		require.False(t, status.Started)
	})

	t.Run("init", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d: %s", code, exp, ui.ErrorWriter.String())
		}

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		status, err := client.Sys().RotateRootStatus()
		require.NoError(t, err)
		require.True(t, status.Started)
	})

	t.Run("init_pgp", func(t *testing.T) {
		t.Parallel()

		pgpKey := "keybase:hashicorp"
		pgpFingerprints := []string{"c874011f0ab405110d02105534365d9472d7468f"}

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
			"-pgp-keys", pgpKey,
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String()
		require.Contains(t, combined, "Nonce")

		status, err := client.Sys().RotateRootStatus()
		require.NoError(t, err)
		require.True(t, status.Started)
		require.ElementsMatch(t, status.PGPFingerprints, pgpFingerprints)
	})

	t.Run("provide_arg_recovery_keys", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerAutoUnseal(t)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().RotateRecoveryInit(&api.RotateInitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		})
		require.NoError(t, err)
		nonce := status.Nonce

		// Supply the first n-1 recovery keys
		for _, key := range keys[:len(keys)-1] {
			ui, cmd := testOperatorRotateKeysCommand(t)
			cmd.client = client

			code := cmd.Run([]string{
				"-nonce", nonce,
				"-target", "recovery",
				key,
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())
		}

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-nonce", nonce,
			"-target", "recovery",
			keys[len(keys)-1], // the last recovery key
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		recoveryKey := match[0][1]

		require.NotContains(t, strings.ToLower(output), "unseal key")

		// verify that we can perform operations with the recovery key
		// below we generate a root token using the recovery key
		rootStatus, err := client.Sys().GenerateRootStatus()
		require.NoError(t, err)

		otp, err := roottoken.GenerateOTP(rootStatus.OTPLength)
		require.NoError(t, err)

		genRoot, err := client.Sys().GenerateRootInit(otp, "")
		require.NoError(t, err)

		r, err := client.Sys().GenerateRootUpdate(recoveryKey, genRoot.Nonce)
		require.NoError(t, err)

		require.True(t, r.Complete)
	})
	t.Run("provide_arg", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerUnseal(t)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().RotateRootInit(&api.RotateInitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		})
		require.NoError(t, err)
		nonce := status.Nonce

		// Supply the first n-1 unseal keys
		for _, key := range keys[:len(keys)-1] {
			ui, cmd := testOperatorRotateKeysCommand(t)
			cmd.client = client

			code := cmd.Run([]string{
				"-nonce", nonce,
				key,
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())
		}

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-nonce", nonce,
			keys[len(keys)-1], // the last unseal key
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		// Grab the unseal key and try to unseal
		unsealKey := match[0][1]
		err = client.Sys().Seal()
		require.NoError(t, err)

		sealStatus, err := client.Sys().Unseal(unsealKey)
		require.NoError(t, err)

		require.False(t, sealStatus.Sealed)
	})

	t.Run("provide_stdin", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerUnseal(t)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().RotateRootInit(&api.RotateInitRequest{
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

			ui, cmd := testOperatorRotateKeysCommand(t)
			cmd.client = client
			cmd.testStdin = stdinR

			code := cmd.Run([]string{
				"-nonce", nonce,
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

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code := cmd.Run([]string{
			"-nonce", nonce,
			"-",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		// Grab the unseal key and try to unseal
		unsealKey := match[0][1]
		err = client.Sys().Seal()
		require.NoError(t, err)

		sealStatus, err := client.Sys().Unseal(unsealKey)
		require.NoError(t, err)

		require.False(t, sealStatus.Sealed)
	})

	t.Run("provide_stdin_recovery_keys", func(t *testing.T) {
		t.Parallel()

		client, keys, closer := testVaultServerAutoUnseal(t)
		defer closer()

		// Initialize rotation
		status, err := client.Sys().RotateRecoveryInit(&api.RotateInitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		})
		require.NoError(t, err)
		nonce := status.Nonce

		for _, key := range keys[:len(keys)-1] {
			stdinR, stdinW := io.Pipe()
			go func() {
				_, _ = stdinW.Write([]byte(key))
				_ = stdinW.Close()
			}()

			ui, cmd := testOperatorRotateKeysCommand(t)
			cmd.client = client
			cmd.testStdin = stdinR

			code := cmd.Run([]string{
				"-target", "recovery",
				"-nonce", nonce,
				"-",
			})
			require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		}

		stdinR, stdinW := io.Pipe()
		go func() {
			_, _ = stdinW.Write([]byte(keys[len(keys)-1])) // the last recovery key
			_ = stdinW.Close()
		}()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code := cmd.Run([]string{
			"-nonce", nonce,
			"-target", "recovery",
			"-",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		re := regexp.MustCompile(`Key 1: (.+)`)
		output := ui.OutputWriter.String()
		match := re.FindAllStringSubmatch(output, -1)
		require.False(t, len(match) < 1 || len(match[0]) < 2)

		recoveryKey := match[0][1]

		require.NotContains(t, strings.ToLower(output), "unseal key")

		// verify that we can perform operations with the recovery key
		// below we generate a root token using the recovery key
		rootStatus, err := client.Sys().GenerateRootStatus()
		require.NoError(t, err)

		otp, err := roottoken.GenerateOTP(rootStatus.OTPLength)
		require.NoError(t, err)

		genRoot, err := client.Sys().GenerateRootInit(otp, "")
		require.NoError(t, err)

		r, err := client.Sys().GenerateRootUpdate(recoveryKey, genRoot.Nonce)
		require.NoError(t, err)
		require.True(t, r.Complete)
	})
	t.Run("backup", func(t *testing.T) {
		t.Parallel()

		pgpKey := "keybase:hashicorp"
		client, keys, closer := testVaultServerUnseal(t)
		defer closer()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-init",
			"-key-shares", "1",
			"-key-threshold", "1",
			"-pgp-keys", pgpKey,
			"-backup",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		// Get the status for the nonce
		status, err := client.Sys().RotateRootStatus()
		require.NoError(t, err)
		nonce := status.Nonce

		var combined string
		// Supply the unseal keys
		for _, key := range keys {
			ui, cmd := testOperatorRotateKeysCommand(t)
			cmd.client = client

			code := cmd.Run([]string{
				"-nonce", nonce,
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
		ui, cmd = testOperatorRotateKeysCommand(t)
		cmd.client = client

		code = cmd.Run([]string{
			"-backup-retrieve",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(t, output, fingerprint)
		require.Contains(t, output, encryptedKey)

		// Delete the backup
		ui, cmd = testOperatorRotateKeysCommand(t)
		cmd.client = client

		code = cmd.Run([]string{
			"-backup-delete",
		})
		require.Equalf(t, 0, code, "expected %d to be %d: %s", code, 0, ui.ErrorWriter.String())

		_, err = client.Sys().RotateRootRetrieveBackup()
		require.Error(t, err)
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testOperatorRotateKeysCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"secret/foo",
		})
		require.Equalf(t, 2, code, "expected %d to be %d: %s", code, 2, ui.ErrorWriter.String())

		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		require.Contains(t, combined, "Error getting rotation status: ")
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testOperatorRotateKeysCommand(t)
		assertNoTabs(t, cmd)
	})
}
