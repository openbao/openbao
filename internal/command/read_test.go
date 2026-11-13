// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testReadCommand(tb testing.TB) (*cli.MockUi, *ReadCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &ReadCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestReadCommand_Run(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		out  string
		code int
	}{
		{
			"not_enough_args",
			[]string{},
			"Not enough arguments",
			1,
		},
		{
			"proper_args",
			[]string{"foo", "bar=baz"},
			"No value found at foo\n",
			2,
		},
		{
			"not_found",
			[]string{"nope/not/once/never"},
			"",
			2,
		},
		{
			"default",
			[]string{"secret/read/foo"},
			"foo",
			0,
		},
		{
			"field",
			[]string{
				"-field", "foo",
				"secret/read/foo",
			},
			"bar",
			0,
		},
		{
			"field_not_found",
			[]string{
				"-field", "not-a-real-field",
				"secret/read/foo",
			},
			"not present",
			1,
		},
	}

	t.Run("validations", func(t *testing.T) {
		t.Parallel()

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				client, closer := testVaultServer(t)
				defer closer()

				if _, err := client.Logical().Write("secret/read/foo", map[string]any{
					"foo": "bar",
				}); err != nil {
					t.Fatal(err)
				}

				ui, cmd := testReadCommand(t)
				cmd.client = client

				code := cmd.Run(tc.args)
				if code != tc.code {
					t.Errorf("expected %d to be %d", code, tc.code)
				}

				combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
				if !strings.Contains(combined, tc.out) {
					t.Errorf("%s: expected %q to contain %q", tc.name, combined, tc.out)
				}
			})
		}
	})

	t.Run("communication_failure", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServerBad(t)
		defer closer()

		ui, cmd := testReadCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"secret/foo",
		})
		if exp := 2; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}

		expected := "Error reading secret/foo: "
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		if !strings.Contains(combined, expected) {
			t.Errorf("expected %q to contain %q", combined, expected)
		}
	})

	t.Run("no_data_object_from_api_response", func(t *testing.T) {
		t.Parallel()

		client, closer := testVaultServer(t)
		defer closer()

		ui, cmd := testReadCommand(t)
		cmd.client = client

		code := cmd.Run([]string{
			"sys/health",
		})
		if exp := 0; code != exp {
			t.Errorf("expected %d to be %d", code, exp)
		}
		combined := ui.OutputWriter.String() + ui.ErrorWriter.String()
		expected := []string{
			"cluster_id", "cluster_name", "initialized", "replication_dr_mode", "replication_performance_mode", "sealed",
			"server_time_utc", "standby", "version",
		}
		for _, expectedField := range expected {
			if !strings.Contains(combined, expectedField) {
				t.Errorf("expected %q to contain %q", combined, expected)
			}
		}
	})

	t.Run("no_tabs", func(t *testing.T) {
		t.Parallel()

		_, cmd := testReadCommand(t)
		assertNoTabs(t, cmd)
	})

	t.Run("gh_issue_4367_non_json_response", func(t *testing.T) {
		t.Parallel()
		type testCase struct {
			name         string
			srv          *httptest.Server
			assertResult func(*testing.T, *cli.MockUi, *ReadCommand)
		}
		const pemBody = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

		var testCases = []testCase{
			{
				name: "non_json_non_404_response_parsed_as_raw",
				srv: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					_, _ = w.Write([]byte(pemBody))
					w.WriteHeader(http.StatusOK)
				})),
				assertResult: func(t *testing.T, ui *cli.MockUi, command *ReadCommand) {
					assert.Equal(t, 0, command.Run([]string{"pki/issuer/test/pem"}), "read returned non-zero result")
					assert.Equal(t, pemBody+"\n", ui.OutputWriter.String(), "reading \"pki/issuer/test/pem\" did not output as raw format")
				},
			},
			{
				name: "json_404_returns_warnings_with_zero_exit_status",
				srv: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"warnings":["something happened"]}`))
					w.WriteHeader(http.StatusNotFound)
				})),
				assertResult: func(t *testing.T, ui *cli.MockUi, command *ReadCommand) {
					assert.Equal(t, 0, command.Run([]string{"pki/issuer/test/pem"}), "bad read exited on 0")
					assert.Equal(t, "WARNING! The following warnings were returned from OpenBao:\n\n  * something happened\n\n", ui.ErrorWriter.String(), "valid 404 not parsed correctly")
				},
			},
			{
				name: "non_json_response_error_with_field_flag",
				srv: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					_, _ = w.Write([]byte(pemBody))
					w.WriteHeader(http.StatusOK)
				})),
				assertResult: func(t *testing.T, ui *cli.MockUi, command *ReadCommand) {
					assert.NotEqual(t, 0, command.Run([]string{"-field", "mycustomfield", "pki/issuer/test/pem"}), "bad read exited on 0")
					assert.Equal(t, "'-field' parameter is not supported when output type is 'raw'\n", ui.ErrorWriter.String(), "error was not loggged when -field passed reading raw secret value")
					assert.Empty(t, ui.OutputWriter.String())
				},
			},
			{
				name: "bad_json_returns_error",
				srv: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte("this is an invalid JSON body"))
					w.WriteHeader(http.StatusOK)
				})),
				assertResult: func(t *testing.T, ui *cli.MockUi, command *ReadCommand) {
					assert.NotEqual(t, 0, command.Run([]string{"pki/issuer/test/pem"}), "bad read exited on 0")
					assert.Equal(t, "Error reading pki/issuer/test/pem: invalid character 'h' in literal true (expecting 'r')\n", ui.ErrorWriter.String(), "reading \"pki/issuer/test/pem\" did not output as raw format")
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				defer tc.srv.Close()
				cfg := api.DefaultConfig()
				cfg.Address = tc.srv.URL
				client, err := api.NewClient(cfg)
				require.NoError(t, err)
				ui, command := testReadCommand(t)
				command.client = client
				tc.assertResult(t, ui, command)
			})
		}
	})
}
