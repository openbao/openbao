// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/version"
)

func testVersionHistoryCommand(tb testing.TB) (*cli.MockUi, *VersionHistoryCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &VersionHistoryCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestVersionHistoryCommand_TableOutput(t *testing.T) {
	client, closer := testVaultServer(t)
	defer closer()

	// Use explicit stdout/stderr buffers (same pattern as JsonOutput test)
	// to avoid data races on cli.MockUi's shared buffers
	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	runOpts := &RunOptions{
		Stdout: stdout,
		Stderr: stderr,
		Client: client,
	}

	args, _, _, _, _ := setupEnv([]string{"version-history"})

	code := RunCustom(args, runOpts)

	if expectedCode := 0; code != expectedCode {
		t.Fatalf("expected exit code %d, got %d: %s", expectedCode, code, stderr.String())
	}

	// versionTrackingWarning is always written to stderr regardless of format.
	if stderrStr := stderr.String(); !strings.Contains(stderrStr, versionTrackingWarning) {
		t.Errorf("expected stderr %q to contain warning %q", stderrStr, versionTrackingWarning)
	}

	// Table output goes to stdout; current binary version must appear.
	if stdoutStr := stdout.String(); !strings.Contains(stdoutStr, version.Version) {
		t.Errorf("expected stdout %q to contain version %q", stdoutStr, version.Version)
	}
}

func TestVersionHistoryCommand_JsonOutput(t *testing.T) {
	client, closer := testVaultServer(t)
	defer closer()

	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	runOpts := &RunOptions{
		Stdout: stdout,
		Stderr: stderr,
		Client: client,
	}

	args, format, _, _, _ := setupEnv([]string{"version-history", "-format", "json"})
	if format != "json" {
		t.Fatalf("expected format to be %q, actual %q", "json", format)
	}

	code := RunCustom(args, runOpts)

	if expectedCode := 0; code != expectedCode {
		t.Fatalf("expected %d to be %d: %s", code, expectedCode, stderr.String())
	}

	if stderrString := stderr.String(); !strings.Contains(stderrString, versionTrackingWarning) {
		t.Errorf("expected %q to contain %q", stderrString, versionTrackingWarning)
	}

	stdoutBytes := stdout.Bytes()

	if !json.Valid(stdoutBytes) {
		t.Fatalf("expected output %q to be valid JSON", stdoutBytes)
	}

	var versionHistoryResp map[string]interface{}
	err := json.Unmarshal(stdoutBytes, &versionHistoryResp)
	if err != nil {
		t.Fatalf("failed to unmarshal json from STDOUT, err: %s", err.Error())
	}

	var respData map[string]interface{}
	var ok bool
	var keys []interface{}
	var keyInfo map[string]interface{}

	if respData, ok = versionHistoryResp["data"].(map[string]interface{}); !ok {
		t.Fatalf("expected data key to be map, actual: %#v", versionHistoryResp["data"])
	}

	if keys, ok = respData["keys"].([]interface{}); !ok {
		t.Fatalf("expected keys to be array, actual: %#v", respData["keys"])
	}

	if keyInfo, ok = respData["key_info"].(map[string]interface{}); !ok {
		t.Fatalf("expected key_info to be map, actual: %#v", respData["key_info"])
	}

	if len(keys) != 1 {
		t.Fatalf("expected single version history entry for %q", version.Version)
	}

	if keyInfo[version.Version] == nil {
		t.Fatalf("expected version %s to be present in key_info, actual: %#v", version.Version, keyInfo)
	}
}
