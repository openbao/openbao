// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/hashicorp/cli"
	colorable "github.com/mattn/go-colorable"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/command/token"
)

type VaultUI struct {
	cli.Ui
	format   string
	detailed bool
}

const (
	globalFlagOutputCurlString = "output-curl-string"
	globalFlagOutputPolicy     = "output-policy"
	globalFlagOutputProfile    = "output-profile"
	globalFlagFormat           = "format"
	globalFlagDetailed         = "detailed"
)

var globalFlags = []string{
	globalFlagOutputCurlString,
	globalFlagOutputPolicy,
	globalFlagOutputProfile,
	globalFlagFormat,
	globalFlagDetailed,
}

// setupEnv parses args and may replace them and sets some env vars to known
// values based on format options
func setupEnv(args []string) (ret struct {
	args             []string
	format           string
	detailed         bool
	outputCurlString bool
	outputPolicy     bool
	outputProfile    bool
},
) {
	var err error
	var nextArgFormat bool
	var haveDetailed bool

	for _, arg := range args {
		if nextArgFormat {
			nextArgFormat = false
			ret.format = arg
			continue
		}

		if arg == "--" {
			break
		}

		if len(args) == 1 && (arg == "-v" || arg == "-version" || arg == "--version") {
			args = []string{"version"}
			break
		}

		if isGlobalFlag(arg, globalFlagOutputCurlString) {
			ret.outputCurlString = true
			continue
		}

		if isGlobalFlag(arg, globalFlagOutputPolicy) {
			ret.outputPolicy = true
			continue
		}

		if isGlobalFlag(arg, globalFlagOutputProfile) {
			ret.outputProfile = true
			continue
		}

		// Parse a given flag here, which overrides the env var
		if isGlobalFlagWithValue(arg, globalFlagFormat) {
			ret.format = getGlobalFlagValue(arg)
		}
		// For backwards compat, it could be specified without an equal sign
		if isGlobalFlag(arg, globalFlagFormat) {
			nextArgFormat = true
		}

		// Parse a given flag here, which overrides the env var
		if isGlobalFlagWithValue(arg, globalFlagDetailed) {
			ret.detailed, err = strconv.ParseBool(getGlobalFlagValue(globalFlagDetailed))
			if err != nil {
				ret.detailed = false
			}
			haveDetailed = true
		}
		// For backwards compat, it could be specified without an equal sign to enable
		// detailed output.
		if isGlobalFlag(arg, globalFlagDetailed) {
			ret.detailed = true
			haveDetailed = true
		}
	}

	envVaultFormat := api.ReadBaoVariable(EnvVaultFormat)
	// If we did not parse a value, fetch the env var
	if ret.format == "" && envVaultFormat != "" {
		ret.format = envVaultFormat
	}
	// Lowercase for consistency
	ret.format = strings.ToLower(ret.format)
	if ret.format == "" {
		ret.format = "table"
	}

	envVaultDetailed := api.ReadBaoVariable(EnvVaultDetailed)
	// If we did not parse a value, fetch the env var
	if !haveDetailed && envVaultDetailed != "" {
		ret.detailed, err = strconv.ParseBool(envVaultDetailed)
		if err != nil {
			ret.detailed = false
		}
	}

	ret.args = args
	return ret
}

func isGlobalFlag(arg string, flag string) bool {
	return arg == "-"+flag || arg == "--"+flag
}

func isGlobalFlagWithValue(arg string, flag string) bool {
	return strings.HasPrefix(arg, "--"+flag+"=") || strings.HasPrefix(arg, "-"+flag+"=")
}

func getGlobalFlagValue(arg string) string {
	_, value, _ := strings.Cut(arg, "=")

	return value
}

type RunOptions struct {
	TokenHelper token.TokenHelper
	Stdout      io.Writer
	Stderr      io.Writer
	Address     string
	Client      *api.Client
}

func Run(args []string) int {
	return RunCustom(args, nil)
}

// RunCustom allows passing in a base command template to pass to other
// commands. Currently, this is only used for setting a custom token helper.
func RunCustom(args []string, runOpts *RunOptions) int {
	if runOpts == nil {
		runOpts = &RunOptions{}
	}

	env := setupEnv(args)

	// Don't use color if disabled
	useColor := !color.NoColor && api.ReadBaoVariable(EnvVaultCLINoColor) == ""

	if runOpts.Stdout == nil {
		runOpts.Stdout = os.Stdout
	}
	if runOpts.Stderr == nil {
		runOpts.Stderr = os.Stderr
	}

	// Only use colored UI if stdout is a tty, and not disabled
	if useColor && env.format == "table" {
		if f, ok := runOpts.Stdout.(*os.File); ok {
			runOpts.Stdout = colorable.NewColorable(f)
		}
		if f, ok := runOpts.Stderr.(*os.File); ok {
			runOpts.Stderr = colorable.NewColorable(f)
		}
	} else {
		runOpts.Stdout = colorable.NewNonColorable(runOpts.Stdout)
		runOpts.Stderr = colorable.NewNonColorable(runOpts.Stderr)
	}

	uiErrWriter := runOpts.Stderr
	if env.outputCurlString || env.outputPolicy || env.outputProfile {
		uiErrWriter = &bytes.Buffer{}
	}

	ui := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      runOpts.Stdout,
				ErrorWriter: uiErrWriter,
			},
		},
		format:   env.format,
		detailed: env.detailed,
	}

	serverCmdUi := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader: bufio.NewReader(os.Stdin),
				Writer: runOpts.Stdout,
			},
		},
		format: env.format,
	}

	if _, ok := Formatters[env.format]; !ok {
		ui.Error(fmt.Sprintf("Invalid output format: %s", env.format))
		return 1
	}

	commands := initCommands(ui, serverCmdUi, runOpts)

	hiddenCommands := []string{"version"}

	cli := &cli.CLI{
		Name:     "bao",
		Args:     env.args,
		Commands: commands,
		HelpFunc: groupedHelpFunc(
			cli.BasicHelpFunc("bao"),
		),
		HelpWriter:                 runOpts.Stdout,
		ErrorWriter:                runOpts.Stderr,
		HiddenCommands:             hiddenCommands,
		Autocomplete:               true,
		AutocompleteNoDefaultFlags: true,
	}

	exitCode, err := cli.Run()
	if env.outputCurlString {
		return generateCurlString(exitCode, runOpts, uiErrWriter.(*bytes.Buffer))
	} else if env.outputPolicy {
		return generatePolicy(exitCode, runOpts, uiErrWriter.(*bytes.Buffer))
	} else if env.outputProfile {
		return generateProfile(exitCode, runOpts, uiErrWriter.(*bytes.Buffer))
	} else if err != nil {
		_, _ = fmt.Fprintf(runOpts.Stderr, "Error executing CLI: %s\n", err.Error())
		return 1
	}

	return exitCode
}

var commonCommands = []string{
	"read",
	"write",
	"delete",
	"list",
	"login",
	"agent",
	"server",
	"status",
	"unwrap",
}

func groupedHelpFunc(_ cli.HelpFunc) cli.HelpFunc {
	return func(commands map[string]cli.CommandFactory) string {
		var b bytes.Buffer
		tw := tabwriter.NewWriter(&b, 0, 2, 6, ' ', 0)

		_, _ = fmt.Fprintf(tw, "Usage: bao <command> [args]\n\n")
		_, _ = fmt.Fprintf(tw, "Common commands:\n")
		for _, v := range commonCommands {
			printCommand(tw, v, commands[v])
		}

		otherCommands := make([]string, 0, len(commands))
		for k := range commands {
			found := slices.Contains(commonCommands, k)

			if !found {
				otherCommands = append(otherCommands, k)
			}
		}
		sort.Strings(otherCommands)

		_, _ = fmt.Fprintf(tw, "\n")
		_, _ = fmt.Fprintf(tw, "Other commands:\n")
		for _, v := range otherCommands {
			printCommand(tw, v, commands[v])
		}

		_ = tw.Flush()

		return strings.TrimSpace(b.String())
	}
}

func printCommand(w io.Writer, name string, cmdFn cli.CommandFactory) {
	cmd, err := cmdFn()
	if err != nil {
		panic(fmt.Sprintf("failed to load %q command: %s", name, err))
	}
	_, _ = fmt.Fprintf(w, "    %s\t%s\n", name, cmd.Synopsis())
}

func generateCurlString(exitCode int, runOpts *RunOptions, preParsingErrBuf *bytes.Buffer) int {
	if exitCode == 0 {
		_, _ = fmt.Fprint(runOpts.Stderr, "Could not generate cURL command")
		return 1
	}

	if api.LastOutputStringError == nil {
		if exitCode == 127 {
			// Usage, just pass it through
			return exitCode
		}
		_, _ = runOpts.Stderr.Write(preParsingErrBuf.Bytes())
		_, _ = fmt.Fprint(runOpts.Stderr, "Unable to generate cURL string from command\n")
		return exitCode
	}

	cs, err := api.LastOutputStringError.CurlString()
	if err != nil {
		_, _ = fmt.Fprintf(runOpts.Stderr, "Error creating request string: %s\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(runOpts.Stdout, "%s\n", cs)
	return 0
}

func generatePolicy(exitCode int, runOpts *RunOptions, preParsingErrBuf *bytes.Buffer) int {
	if exitCode == 0 {
		_, _ = fmt.Fprint(runOpts.Stderr, "Could not generate policy")
		return 1
	}

	if api.LastOutputPolicyError == nil {
		if exitCode == 127 {
			// Usage, just pass it through
			return exitCode
		}
		_, _ = runOpts.Stderr.Write(preParsingErrBuf.Bytes())
		_, _ = fmt.Fprint(runOpts.Stderr, "Unable to generate policy from command\n")
		return exitCode
	}

	hcl, err := api.LastOutputPolicyError.HCLString()
	if err != nil {
		_, _ = fmt.Fprintf(runOpts.Stderr, "Error assembling policy HCL: %s\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(runOpts.Stdout, "%s\n", hcl)
	return 0
}

func generateProfile(exitCode int, runOpts *RunOptions, preParsingErrBuf *bytes.Buffer) int {
	if exitCode == 0 {
		_, _ = fmt.Fprint(runOpts.Stderr, "Could not generate profile")
		return 1
	}

	if api.LastOutputProfileError == nil {
		if exitCode == 127 {
			// Usage, just pass it through
			return exitCode
		}
		_, _ = runOpts.Stderr.Write(preParsingErrBuf.Bytes())
		_, _ = fmt.Fprint(runOpts.Stderr, "Unable to generate profile from command\n")
		return exitCode
	}

	hcl, err := api.LastOutputProfileError.HCLString()
	if err != nil {
		_, _ = fmt.Fprintf(runOpts.Stderr, "Error assembling profile HCL: %s\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(runOpts.Stdout, "%s\n", hcl)
	return 0
}
