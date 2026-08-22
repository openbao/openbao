// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
)

func testWorkflowEditCommand(tb testing.TB) (*cli.MockUi, *WorkflowEditCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &WorkflowEditCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestWorkflowEditCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"not_enough_args",
			nil,
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
			"non_interactive",
			[]string{"-non-interactive", "my-workflow"},
			"Refusing to edit",
			1,
		},
		{
			"not_found",
			[]string{"-editor=do-not-matter", "not-a-real-workflow"},
			"Error finding workflow to edit under path not-a-real-workflow",
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

				ui, cmd := testWorkflowEditCommand(t)
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

	t.Run("editor_does_not_exist", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		workflow := string(testWorkflowContents(t))
		if _, err := client.Sys().PutWorkflow("my-workflow", api.PutWorkflowInput{Workflow: workflow}); err != nil {
			t.Fatal(err)
		}

		ui, cmd := testWorkflowEditCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-editor=" + filepath.Join(t.TempDir(), "does-not-exist"), "my-workflow",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Failed to edit workflow"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testWorkflowEditCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-editor=i-use-vim-btw", "my-workflow",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error finding workflow to edit under path my-workflow: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testWorkflowEditCommand(t)
		assertNoTabs(t, cmd)
	})
}
