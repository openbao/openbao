// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	log "github.com/hashicorp/go-hclog"

	"github.com/openbao/openbao/vault/diagnose"
	"github.com/openbao/openbao/version"
	"github.com/posener/complete"
	"golang.org/x/term"
)

var (
	_ cli.Command             = (*OperatorValidateConfigCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorValidateConfigCommand)(nil)
)

type OperatorValidateConfigCommand struct {
	*BaseCommand
	diagnose *diagnose.Session

	flagConfigs []string
}

func (c *OperatorValidateConfigCommand) Synopsis() string {
	return "Validate OpenBao configuration files"
}

func (c *OperatorValidateConfigCommand) Help() string {
	helpText := `
Usage: bao operator validate-config

  This command validates OpenBao configuration.
  It will detect invalid syntax, unknown properties and invalid types.
  Some problems like wrong cluster_addr (i.e. a missing DNS entry) won't be
  detected as this can only be detected at runtime.
  Some problems are deliberately not detected, e.g. that the raft path is writable.
  This is to ensure that a configuration can be validated on a different machine
  for example an operators laptop or during Pull Request validation.
  To include this kind of tests use  "bao operator diagnose" instead.

  Validate a configuration file:

     $ bao operator validate-config -config=/etc/openbao/config.hcl

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorValidateConfigCommand) Flags() *FlagSets {
	set := NewFlagSets(c.UI)
	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
			complete.PredictDirs("*"),
		),
		Usage: "Path to an OpenBao configuration file or directory of configuration " +
			"files. This flag can be specified multiple times to load multiple " +
			"configurations. If the path is a directory, all files which end in " +
			".hcl or .json are loaded.",
	})

	f.StringVar(&StringVar{
		Name:   "format",
		Target: &c.flagFormat,
		Usage:  "The output format",
	})

	return set
}

func (c *OperatorValidateConfigCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *OperatorValidateConfigCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorValidateConfigCommand) Run(args []string) int {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 3
	}
	return c.RunWithParsedFlags()
}

func (c *OperatorValidateConfigCommand) RunWithParsedFlags() int {
	if len(c.flagConfigs) == 0 {
		c.UI.Error("Must specify a configuration file using -config.")
		return 3
	}

	if c.diagnose == nil {
		if c.flagFormat == "json" {
			c.diagnose = diagnose.New(io.Discard)
		} else {
			c.UI.Output(version.GetVersion().FullVersionNumber(true))
			c.diagnose = diagnose.New(os.Stdout)
		}
	}
	ctx := diagnose.Context(context.Background(), c.diagnose)
	c.validateConfig(ctx)

	results := c.diagnose.Finalize(ctx)
	if c.flagFormat == "json" {
		resultsJS, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling results: %v.", err)
			return 4
		}
		c.UI.Output(string(resultsJS))
	} else {
		w, _, err := term.GetSize(0)
		if err == nil {
			w = 0
		}
		err = results.Write(os.Stdout, w)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error printing results: %v.", err)
			return 4
		}
	}

	// Use a different return code
	switch results.Status {
	case diagnose.WarningStatus:
		return 2
	case diagnose.ErrorStatus:
		return 1
	}
	return 0
}

func (c *OperatorValidateConfigCommand) validateConfig(ctx context.Context) {
	server := &ServerCommand{
		BaseCommand: c.BaseCommand,

		logger: log.NewInterceptLogger(&log.LoggerOptions{
			Level: log.Off,
		}),
		allLoggers: []log.Logger{},
	}

	ctx, span := diagnose.StartSpan(ctx, "Validate Config")
	defer span.End()

	server.flagConfigs = c.flagConfigs

	_, configErrors, err := server.parseConfig()
	if err != nil {
		diagnose.Fail(ctx, fmt.Sprintf("Could not parse configuration: %v.", err))
		return
	}
	for _, ce := range configErrors {
		diagnose.Warn(ctx, diagnose.CapitalizeFirstLetter(ce.String())+".")
		return
	}

	diagnose.Success(ctx, "Vault configuration syntax is ok.")
}
