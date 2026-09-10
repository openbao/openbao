// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
)

func testWorkflowWriteCommand(tb testing.TB) (*cli.MockUi, *WorkflowWriteCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &WorkflowWriteCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func testWorkflowContents(tb testing.TB) []byte {
	tb.Helper()

	return bytes.TrimSpace([]byte(`
flow "check" {
  request "status" {
    operation = "read"
    path = "sys/seal-status"
  }
}
	`))
}

func TestWorkflowWriteCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"not_enough_args",
			[]string{"my-workflow"},
			"Not enough arguments",
			1,
		},
		{
			"too_many_args",
			[]string{"foo", "bar", "baz"},
			"Too many arguments",
			1,
		},
		{
			"bad_file",
			[]string{"my-workflow", "/not/a/real/path.hcl"},
			"Error opening workflow file",
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

				ui, cmd := testWorkflowWriteCommand(t)
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

	t.Run("file", func(t *testing.T) {
		t.Parallel()

		workflow := testWorkflowContents(t)
		f, err := os.CreateTemp("", "vault-workflow-write")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(workflow); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name()) //nolint:errcheck

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testWorkflowWriteCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"my-workflow", f.Name(),
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Success! Wrote workflow: my-workflow"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}

		resp, err := client.Sys().GetWorkflow(context.Background(), "my-workflow")
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a workflow response")
		}
		if resp.Version != 1 {
			t.Errorf("expected version %d to be %d", resp.Version, 1)
		}
		if strings.TrimSpace(resp.Workflow) != string(workflow) {
			t.Errorf("expected %q to be %q", resp.Workflow, workflow)
		}
	})

	t.Run("stdin", func(t *testing.T) {
		t.Parallel()

		stdinR, stdinW := io.Pipe()
		go func() {
			workflow := testWorkflowContents(t)
			stdinW.Write(workflow) //nolint:errcheck
			stdinW.Close()         //nolint:errcheck
		}()

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testWorkflowWriteCommand(t)
		cmd.client = client
		cmd.testStdin = stdinR

		code := cmd.Run([]string{
			"my-workflow", "-",
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Success! Wrote workflow: my-workflow"
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("flags", func(t *testing.T) {
		t.Parallel()

		workflow := testWorkflowContents(t)
		f, err := os.CreateTemp("", "vault-workflow-write")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(workflow); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name()) //nolint:errcheck

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testWorkflowWriteCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"-description", "my description",
			"-allow-unauthenticated",
			"-cas-required",
			"-cas=-1",
			"my-workflow", f.Name(),
		})
		if exp := 0; exp != code {
			combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
			t.Fatalf("expected %d to be %d: %s", code, exp, combined)
		}

		resp, err := client.Sys().GetWorkflow(context.Background(), "my-workflow")
		if err != nil {
			t.Fatal(err)
		}
		if resp.Description != "my description" {
			t.Errorf("expected description %q to be %q", resp.Description, "my description")
		}
		if !resp.AllowUnauthenticated {
			t.Error("expected allow_unauthenticated to be true")
		}
		if !resp.CasRequired {
			t.Error("expected cas_required to be true")
		}

		// A second write without -cas should now fail since cas is required.
		ui, cmd = testWorkflowWriteCommand(t)
		cmd.client = client

		code = cmd.Run([]string{"my-workflow", f.Name()})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error writing workflow at path my-workflow: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}

		// A write with an incorrect cas should also fail.
		ui, cmd = testWorkflowWriteCommand(t)
		cmd.client = client

		code = cmd.Run([]string{"-cas=99", "my-workflow", f.Name()})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		combined = ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}

		// A write with the correct cas should succeed.
		ui, cmd = testWorkflowWriteCommand(t)
		cmd.client = client

		code = cmd.Run([]string{"-cas=1", "my-workflow", f.Name()})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected = "Success! Wrote workflow: my-workflow"
		combined = ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testWorkflowWriteCommand(t)
		cmd.client = client
		cmd.testStdin = bytes.NewReader(testWorkflowContents(t))

		code := cmd.Run([]string{
			"my-workflow", "-",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error writing workflow at path my-workflow: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testWorkflowWriteCommand(t)
		assertNoTabs(t, cmd)
	})
}
