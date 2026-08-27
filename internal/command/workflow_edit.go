// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/pmezard/go-difflib/difflib"
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
  can be defined via a flag or the EDITOR environment variable. If
  saving fails, you will be prompted to retry editing, overwrite
  the latest version on the server, view a diff against the latest
  version, or discard your changes.

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
		Default: "vi",
		EnvVar:  "EDITOR",
		Usage:   "The editor you want to use. Defaults to '$EDITOR' and then falls back to 'vi'",
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

	workflowResp, err := client.Sys().GetWorkflow(context.Background(), path)
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
	defer func() {
		tmpFile.Close() //nolint:errcheck
		if retcode == 0 {
			os.Remove(tmpFile.Name()) //nolint:errcheck
		}
	}()

	if err := os.Chmod(tmpFile.Name(), 0o600); err != nil {
		c.UI.Error(fmt.Sprintf("Error setting temporary workflow file permissions: %s", err))
		os.Remove(tmpFile.Name()) //nolint:errcheck
		return 2
	}
	currentWorkflowBytes := []byte(workflowResp.Workflow)
	if err := os.WriteFile(tmpFile.Name(), currentWorkflowBytes, 0o600); err != nil {
		c.UI.Error(fmt.Sprintf("Error writing temporary workflow file permissions: %s", err))
		os.Remove(tmpFile.Name()) //nolint:errcheck
		return 2
	}

Edit:
	for {
		tmpFileContent, ok, code := c.openInEditor(tmpFile.Name())
		if !ok {
			return code
		}

		if bytes.Equal(currentWorkflowBytes, tmpFileContent) || len(tmpFileContent) == 0 {
			c.UI.Info("Edit unchanged or empty, aborting.")
			return 0
		}

	Retry:
		for {
			workflowInput := api.PutWorkflowInput{
				Workflow:             string(tmpFileContent),
				Description:          workflowResp.Description,
				AllowUnauthenticated: workflowResp.AllowUnauthenticated,
				CASRequired:          workflowResp.CasRequired,
				CAS:                  &workflowResp.Version,
			}
			if _, putErr := client.Sys().PutWorkflow(context.Background(), path, workflowInput); putErr != nil {
				latest, err := client.Sys().GetWorkflow(context.Background(), path)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error fetching latest workflow under path %s: %s", path, err))
					c.UI.Error(fmt.Sprintf("Your edits are still available in %s", tmpFile.Name()))
					return 2
				}
				if latest == nil {
					c.UI.Error(fmt.Sprintf("No workflow found in path %s", path))
					c.UI.Error(fmt.Sprintf("Your edits are still available in %s", tmpFile.Name()))
					return 2
				}
				c.UI.Error(fmt.Sprintf("Error putting workflow under path %s: %s", path, putErr))

				for {
					answer, err := c.UI.Ask("Retry editing, overwrite with the latest version, view a diff, or discard your changes? [edit/overwrite/diff/discard]")
					if err != nil {
						c.UI.Error(fmt.Sprintf("Error reading answer: %s", err))
						c.UI.Error(fmt.Sprintf("Your edits are still available in %s", tmpFile.Name()))
						return 2
					}
					switch strings.ToLower(strings.TrimSpace(answer)) {
					case "edit":
						continue Edit
					case "overwrite":
						workflowResp = latest
						continue Retry
					case "diff":
						if err := c.diffAgainst(tmpFileContent, []byte(latest.Workflow)); err != nil {
							c.UI.Error(fmt.Sprintf("Error running diff: %s", err))
						}
						continue
					default:
						c.UI.Info("Discarded changes.")
						os.Remove(tmpFile.Name()) //nolint:errcheck
						return 2
					}
				}
			}

			c.UI.Info(fmt.Sprintf("Success! Edited workflow: %s", path))
			return 0
		}
	}
}

func (c *WorkflowEditCommand) diffAgainst(localContent, remoteContent []byte) error {
	text, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(localContent)),
		B:        difflib.SplitLines(string(remoteContent)),
		FromFile: "your edit",
		ToFile:   "online version",
		Context:  3,
	})
	if err != nil {
		return err
	}
	if text == "" {
		c.UI.Info("No differences.")
		return nil
	}
	c.UI.Output(text)
	return nil
}

func (c *WorkflowEditCommand) openInEditor(path string) (content []byte, ok bool, retcode int) {
	cmd := exec.Command(c.flagEditor, path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		exitCode := 2

		if exitError, isExitErr := err.(*exec.ExitError); isExitErr {
			if exitError.Success() {
				c.UI.Info("User exited edit, aborting.")
				return nil, false, 0
			}
			if ws, isWaitStatus := exitError.Sys().(syscall.WaitStatus); isWaitStatus {
				exitCode = ws.ExitStatus()
			}
		}

		c.UI.Error(fmt.Sprintf("Failed to edit workflow: %s", err))
		return nil, false, exitCode
	}

	content, err := os.ReadFile(path)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error read temporary workflow file after changes: %s", err))
		return nil, false, 2
	}
	return content, true, 0
}
