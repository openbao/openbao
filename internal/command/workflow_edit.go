// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowEditCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowEditCommand)(nil)
)

type WorkflowEditCommand struct {
	*BaseCommand

	flagEditor string
}

func (c *WorkflowEditCommand) Synopsis() string {
	return "Edit a workflow"
}

func (c *WorkflowEditCommand) Help() string {
	helpText := `
Usage: bao workflow edit [options] PATH

  Edit a existing workflow under the given PATH. The used editor
  can be defined via a flag or the EDITOR environment variable.

  Edit a workflow:

      $ bao workflow edit my-workflow

  Edit a workflow with vim:

      $ bao workflow edit -editor=vim my-workflow

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowEditCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "editor",
		Target:  &c.flagEditor,
		Default: "editor",
		EnvVar:  "EDITOR",
		Usage:   "The editor you want to use. Defaults to 'editor'",
	})

	return set
}

func (c *WorkflowEditCommand) AutocompleteArgs() complete.Predictor {
	return c.PredictVaultWorkflows()
}

func (c *WorkflowEditCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowEditCommand) Run(args []string) (retcode int) {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.flagNonInteractive {
		c.UI.Error(wrapAtLength("Refusing to edit workflow with -non-interactive specified; use bao workflow write"))
		return 1
	}

	args = f.Args()
	switch {
	case len(args) < 1:
		c.UI.Error(fmt.Sprintf("Not enough arguments (expected 1, got %d)", len(args)))
		return 1
	case len(args) > 1:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1, got %d)", len(args)))
		return 1
	}

	path := strings.TrimSpace(strings.ToLower(sanitizePath(args[0])))

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	workflowResp, err := client.Sys().GetWorkflow(path)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error finding workflow to edit under path %s: %s", path, err))
		return 2
	}
	if workflowResp == nil {
		c.UI.Error(fmt.Sprintf("No workflow found in path %s", path))
		return 2
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("workflow-%s-*.hcl", strings.ReplaceAll(path, "/", "_")))
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating temporary workflow file: %s", err))
		return 2
	}
	defer os.Remove(tmpFile.Name()) //nolint:errcheck

	if err := os.Chmod(tmpFile.Name(), 0o640); err != nil {
		c.UI.Error(fmt.Sprintf("Error setting temporary workflow file permissions: %s", err))
		return 2
	}
	currentWorkflowBytes := []byte(workflowResp.Workflow)
	if err := os.WriteFile(tmpFile.Name(), currentWorkflowBytes, 0o640); err != nil {
		c.UI.Error(fmt.Sprintf("Error writing temporary workflow file permissions: %s", err))
		return 2
	}

	cmd := exec.Command(c.flagEditor, tmpFile.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	if err != nil {
		exitCode := 2

		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.Success() {
				c.UI.Info("User exited edit, aborting.")
				return 0
			}
			if ws, ok := exitError.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		}

		c.UI.Error(fmt.Sprintf("Failed to edit workflow: %s", err))
		return exitCode
	}

	tmpFileContent, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error read temporary workflow file after changes: %s", err))
		return 2
	}

	if bytes.Equal(currentWorkflowBytes, tmpFileContent) {
		c.UI.Info("Edit unchanged, aborting.")
		return 0
	}

	workflowInput := api.PutWorkflowInput{
		Workflow:             string(tmpFileContent),
		Description:          workflowResp.Description,
		AllowUnauthenticated: workflowResp.AllowUnauthenticated,
		CASRequired:          workflowResp.CasRequired,
	}
	if workflowResp.CasRequired {
		workflowInput.CAS = &workflowResp.Version
	}
	if _, err := client.Sys().PutWorkflow(path, workflowInput); err != nil {
		c.UI.Error(fmt.Sprintf("Error putting workflow under path %s: %s", path, err))
		return 2
	}

	c.UI.Info(fmt.Sprintf("Success! Edited workflow: %s", path))
	return 0
}
