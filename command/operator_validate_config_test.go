// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !race

package command

import (
	"io"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/vault/diagnose"
	"github.com/stretchr/testify/require"
)

func testOperatorValidateConfigCommand(tb testing.TB) *OperatorValidateConfigCommand {
	tb.Helper()

	ui := cli.NewMockUi()
	return &OperatorValidateConfigCommand{
		diagnose: diagnose.New(io.Discard),
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestOperatorValidateConfigCommand_Run(t *testing.T) {
	t.Parallel()

	warn := func(warnings ...string) diagnose.Result {
		return diagnose.Result{
			Name:     "Validate Config",
			Status:   diagnose.WarningStatus,
			Message:  "",
			Warnings: warnings,
		}
	}

	expectedErrors := map[string]diagnose.Result{
		"config2.hcl.json":                        warn("Unknown or unsupported field sentinel found in configuration"),
		"config2.hcl":                             warn("Unknown or unsupported field sentinel found in configuration"),
		"config3.hcl":                             warn("Unknown or unsupported field sentinel found in configuration"),
		"config.hcl":                              warn("Unknown or unsupported field sentinel found in configuration"),
		"config_raft.hcl":                         warn("Unknown or unsupported field sentinel found in configuration"),
		"tls_config_ok.hcl":                       warn("Unknown or unsupported field sentinel found in configuration"),
		"diagnose_unknown_property.hcl":           warn("Unknown or unsupported field unknown found in configuration"),
		"hcp_link_config.hcl":                     warn("Unknown or unsupported field cloud found in configuration"),
		"config_bad_https_storage.hcl":            warn("Unknown or unsupported field sentinel found in configuration"),
		"diagnose_bad_https_consul_sr.hcl":        warn("Unknown or unsupported field sentinel found in configuration"),
		"config5.hcl":                             warn("Unknown or unsupported field sentinel found in configuration"),
		"config.hcl.json":                         warn("Unknown or unsupported field sentinel found in configuration"),
		"config_diagnose_hastorage_bad_https.hcl": warn("Unknown or unsupported field sentinel found in configuration"),
		"diagnose_bad_syntax.hcl": {
			Name:    "Validate Config",
			Status:  diagnose.ErrorStatus,
			Message: "expected: IDENT | STRING got: LBRACE",
		},
	}

	files, err := os.ReadDir("./server/test-fixtures/")
	require.NoError(t, err)

	test := func(filename string, expected diagnose.Result) {
		t.Run(filename, func(t *testing.T) {
			t.Parallel()
			cmd := testOperatorValidateConfigCommand(t)

			cmd.Run([]string{"-config", path.Join("./server/test-fixtures/", filename)})
			result := cmd.diagnose.Finalize(t.Context())

			if err := compareResult(&expected, result); err != nil {
				t.Fatalf("Did not find expected test results: %v", err)
			}
		})
	}

	for _, file := range files {
		expected, ok := expectedErrors[file.Name()]
		if !ok {
			expected = diagnose.Result{
				Name:    "Validate Config",
				Status:  diagnose.OkStatus,
				Message: "",
			}
		}

		test(file.Name(), expected)
	}

	test("./file/not.found", diagnose.Result{
		Name:    "Validate Config",
		Status:  diagnose.ErrorStatus,
		Message: "no such file or directory",
	})
}
