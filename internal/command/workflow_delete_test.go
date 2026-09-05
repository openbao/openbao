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

func testWorkflowDeleteCommand(tb testing.TB) (*cli.MockUi, *WorkflowDeleteCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &WorkflowDeleteCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestWorkflowDeleteCommand_Run(t *testing.T) {
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
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, closer := testVaultServer(t)
				defer closer()

				ui, cmd := testWorkflowDeleteCommand(t)
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

	t.Run("integration", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		workflow := string(testWorkflowContents(t))
		if _, err := client.Sys().PutWorkflow(context.Background(), "my-workflow", api.WorkflowInput{
			Workflow: workflow,
		}); err != nil {
			t.Fatal(err)
		}

		ui, cmd := testWorkflowDeleteCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"my-workflow",
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Success! Deleted workflow: my-workflow"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}

		workflows, err := client.Sys().ListWorkflows(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(workflows) != 0 {
			t.Errorf("expected no workflows, got %q", workflows)
		}
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testWorkflowDeleteCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"my-workflow",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error deleting workflow at path my-workflow: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testWorkflowDeleteCommand(t)
		assertNoTabs(t, cmd)
	})
}
