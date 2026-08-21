// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/structtomap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkflowWriteCommand)(nil)
	_ cli.CommandAutocomplete = (*WorkflowWriteCommand)(nil)
)

type WorkflowWriteCommand struct {
	*BaseCommand

	flagDescription          string
	flagAllowUnauthenticated bool
	flagCASRequired          bool
	flagCAS                  int

	testStdin io.Reader // for tests
}

func (c *WorkflowWriteCommand) Synopsis() string {
	return "Creates or updates a workflow"
}

func (c *WorkflowWriteCommand) Help() string {
	helpText := `
Usage: bao workflow write [options] PATH WORKFLOW_FILE

  Creates a new workflow or updates an existing workflow under the given
  PATH, using the workflow document read from WORKFLOW_FILE. Like all HCL
  documents, this may alternatively be JSON encoded. If WORKFLOW_FILE is
  "-", the workflow is read from stdin.

  Create or update a workflow named "my-workflow" from "./workflow.hcl"
  on the local disk:

      $ bao workflow write my-workflow ./workflow.hcl

  Create or update a workflow from stdin:

      $ cat my-workflow.hcl | bao workflow write my-workflow -

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *WorkflowWriteCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "description",
		Target:  &c.flagDescription,
		Default: "",
		Usage:   "Textual description of this workflow for operators.",
	})

	f.BoolVar(&BoolVar{
		Name:    "allow-unauthenticated",
		Target:  &c.flagAllowUnauthenticated,
		Default: false,
		Usage: "Specifies if this workflow is allowed to be executed by " +
			"unauthenticated users. Requires setting the " +
			"allow_unauthenticated_workflows configuration option.",
	})

	f.BoolVar(&BoolVar{
		Name:    "cas-required",
		Target:  &c.flagCASRequired,
		Default: false,
		Usage:   "Whether check-and-set semantics are required to update this workflow.",
	})

	f.IntVar(&IntVar{
		Name:   "cas",
		Target: &c.flagCAS,
		Usage: "Last version number for modifications. Set to -1 for creation " +
			"of a new workflow. Required if the workflow has cas_required set.",
	})

	return set
}

func (c *WorkflowWriteCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *WorkflowWriteCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *WorkflowWriteCommand) Run(args []string) (retcode int) {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	var cas *int
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == "cas" {
			cas = &c.flagCAS
		}
	})

	args = f.Args()
	switch {
	case len(args) < 2:
		c.UI.Error(fmt.Sprintf("Not enough arguments (expected 2, got %d)", len(args)))
		return 1
	case len(args) > 2:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 2, got %d)", len(args)))
		return 1
	}

	path := strings.TrimSpace(strings.ToLower(sanitizePath(args[0])))
	filePath := strings.TrimSpace(args[1])

	// Get the workflow contents, either from stdin or a file
	var reader io.Reader
	if filePath == "-" {
		reader = os.Stdin
		if c.testStdin != nil {
			reader = c.testStdin
		}
	} else {
		file, err := os.Open(filePath)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error opening workflow file: %s", err))
			return 2
		}
		defer func() {
			if err := file.Close(); err != nil {
				c.UI.Error(fmt.Sprintf("Error closing workflow file: %s", err))
				retcode = 2
			}
		}()
		reader = file
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		c.UI.Error(fmt.Sprintf("Error reading workflow: %s", err))
		return 2
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	input := api.PutWorkflowInput{
		Workflow:             buf.String(),
		Description:          c.flagDescription,
		AllowUnauthenticated: c.flagAllowUnauthenticated,
		CASRequired:          c.flagCASRequired,
		CAS:                  cas,
	}

	workflowResp, err := client.Sys().PutWorkflow(path, input)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error writing workflow at path %s: %s", path, err))
		return 2
	}

	if Format(c.UI) == "table" {
		c.UI.Output(fmt.Sprintf("Success! Wrote workflow: %s", path))
		return 0
	}

	data := structtomap.Map(workflowResp)
	if c.flagField != "" {
		return PrintRawField(c.UI, data, c.flagField)
	}
	return OutputData(c.UI, data)
}
