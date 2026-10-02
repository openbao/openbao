// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
)

func testWorkflowListCommand(tb testing.TB) (*cli.MockUi, *WorkflowListCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &WorkflowListCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestWorkflowListCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"too_many_args",
			[]string{"foo"},
			"Too many arguments",
			1,
		},
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, closer := testVaultServer(t)
				defer closer()

				ui, cmd := testWorkflowListCommand(t)
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

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testWorkflowListCommand(t)
		cmd.client = client

		code := cmd.Run([]string{})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "No workflows found"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("default", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		workflow := string(testWorkflowContents(t))
		if _, err := client.Sys().PutWorkflow(context.Background(), "my-workflow", api.WorkflowInput{
			Workflow: workflow,
		}); err != nil {
			t.Fatal(err)
		}

		ui, cmd := testWorkflowListCommand(t)
		cmd.client = client

		code := cmd.Run([]string{})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "my-workflow"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testWorkflowListCommand(t)
		cmd.client = client

		code := cmd.Run([]string{})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error reading workflows: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testWorkflowListCommand(t)
		assertNoTabs(t, cmd)
	})
}
