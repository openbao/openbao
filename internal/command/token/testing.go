// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/stretchr/testify/require"
)

// Test is a public function that can be used in other tests to
// test that a helper is functioning properly.
func Test(t *testing.T, h TokenHelper) {
	require.NoError(t, h.Store("foo"))

	v, err := h.Get()
	require.NoError(t, err)

	if v != "foo" {
		t.Fatalf("bad: %#v", v)
	}

	require.NoError(t, h.Erase())

	v, err = h.Get()
	require.NoError(t, err)

	if v != "" {
		t.Fatalf("bad: %#v", v)
	}
}

// TestProcess is used to re-execute this test in order to use it as the
// helper process. For this to work, the TestExternalTokenHelperProcess function must
// exist.
func TestProcess(t *testing.T, s ...string) {
	h := &ExternalTokenHelper{BinaryPath: TestProcessPath(t, s...)}
	Test(t, h)
}

// TestProcessPath returns the path to the test process.
func TestProcessPath(t *testing.T, s ...string) string {
	cs := []string{"-test.run=TestExternalTokenHelperProcess", "--", "GO_WANT_HELPER_PROCESS"}
	cs = append(cs, s...)
	return fmt.Sprintf(
		"%s %s",
		os.Args[0],
		strings.Join(cs, " "),
	)
}

// TestExternalTokenHelperProcessCLI can be called to implement TestExternalTokenHelperProcess
// for TestProcess that just executes a CLI command.
func TestExternalTokenHelperProcessCLI(t *testing.T, cmd cli.Command) {
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}

		args = args[1:]
	}
	if len(args) == 0 || args[0] != "GO_WANT_HELPER_PROCESS" {
		return
	}
	args = args[1:]

	os.Exit(cmd.Run(args))
}
