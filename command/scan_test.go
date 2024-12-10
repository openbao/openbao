// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"
	"testing"

	"github.com/hashicorp/cli"
)

func testScanCommand(tb testing.TB) (*cli.MockUi, *ScanCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &ScanCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestScanCommand_Run(t *testing.T) {
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
		{
			"not_found",
			[]string{"nope/not/once/never"},
			"",
			2,
		},
		{
			"default",
			[]string{"secret/scan"},
			"bar\nbaz\nfoo",
			0,
		},
		{
			"default_slash",
			[]string{"secret/scan/"},
			"bar\nbaz\nfoo",
			0,
		},
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			tc := tc

			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, closer := testVaultServer(t)
				defer closer()

				keys := []string{
					"secret/scan/foo",
					"secret/scan/bar",
					"secret/scan/baz",
				}
				for _, k := range keys {
					if _, err := client.Logical().Write(k, map[string]interface{}{
						"foo": "bar",
					}); err != nil {
						t.Fatal(err)
					}
				}

				ui, cmd := testScanCommand(t)
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
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testScanCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"secret/scan",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error scanning secret/scan: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testScanCommand(t)
		assertNoTabs(t, cmd)
	})
}
