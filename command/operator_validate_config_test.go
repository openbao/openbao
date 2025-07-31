// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !race

package command

import (
	"io"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/vault/diagnose"
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
	cases := []struct {
		name     string
		args     []string
		expected diagnose.Result
	}{
		{
			"file_not_found",
			[]string{
				"-config", "./file/not.found",
			},
			diagnose.Result{
				Name:    "Validate Config",
				Status:  diagnose.ErrorStatus,
				Message: "no such file or directory.",
			},
		}, {
			"invalid_syntax",
			[]string{
				"-config", "./server/test-fixtures/diagnose_bad_syntax.hcl",
			},
			diagnose.Result{
				Name:    "Validate Config",
				Status:  diagnose.ErrorStatus,
				Message: "expected: IDENT | STRING got: LBRACE",
			},
		}, {
			"unknown_property",
			[]string{
				"-config", "./server/test-fixtures/diagnose_unknown_property.hcl",
			},
			diagnose.Result{
				Name:     "Validate Config",
				Status:   diagnose.WarningStatus,
				Message:  "",
				Warnings: []string{"Unknown or unsupported field unknown found in configuration"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := testOperatorValidateConfigCommand(t)

			cmd.Run(tc.args)
			result := cmd.diagnose.Finalize(t.Context())

			if err := compareResult(&tc.expected, result); err != nil {
				t.Fatalf("Did not find expected test results: %v", err)
			}
		})
	}
}
