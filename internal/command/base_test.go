// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

func getDefaultCliHeaders(t *testing.T) http.Header {
	bc := &BaseCommand{}
	cli, err := bc.Client()
	if err != nil {
		t.Fatal(err)
	}
	return cli.Headers()
}

func isolateHeaderEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv(api.EnvVaultHeaders, "")
	t.Setenv(api.UpstreamVariableName(api.EnvVaultHeaders), "")
}

func TestClient_FlagHeader(t *testing.T) {
	isolateHeaderEnvironment(t)
	defaultHeaders := getDefaultCliHeaders(t)

	cases := []struct {
		Input map[string]string
		Valid bool
	}{
		{
			map[string]string{},
			true,
		},
		{
			map[string]string{"foo": "bar", "header2": "value2"},
			true,
		},
		{
			map[string]string{"X-Vault-foo": "bar", "header2": "value2"},
			false,
		},
	}

	for _, tc := range cases {
		expectedHeaders := defaultHeaders.Clone()
		for key, val := range tc.Input {
			expectedHeaders.Add(key, val)
		}

		bc := &BaseCommand{flagHeader: tc.Input}
		cli, err := bc.Client()

		if err == nil && !tc.Valid {
			t.Errorf("No error for input[%#v], but not valid", tc.Input)
			continue
		}

		if err != nil {
			if tc.Valid {
				t.Errorf("Error[%v] with input[%#v], but valid", err, tc.Input)
			}
			continue
		}

		if cli == nil {
			t.Error("client should not be nil")
		}

		actualHeaders := cli.Headers()
		if !reflect.DeepEqual(expectedHeaders, actualHeaders) {
			t.Errorf("expected [%#v] but got [%#v]", expectedHeaders, actualHeaders)
		}
	}
}

func TestClient_EnvironmentHeader(t *testing.T) {
	isolateHeaderEnvironment(t)
	t.Setenv(api.EnvVaultHeaders, `{"X-IAP-Token":"token"}`)

	client, err := (&BaseCommand{}).Client()
	require.NoError(t, err)
	require.Equal(t, []string{"token"}, client.Headers().Values("X-IAP-Token"))
}

func TestClient_EnvironmentAndFlagHeader(t *testing.T) {
	isolateHeaderEnvironment(t)
	t.Setenv(api.EnvVaultHeaders, `{"X-IAP-Token":"environment"}`)

	client, err := (&BaseCommand{
		flagHeader: map[string]string{"X-IAP-Token": "flag"},
	}).Client()
	require.NoError(t, err)
	require.Equal(t, []string{"environment", "flag"}, client.Headers().Values("X-IAP-Token"))
}

func TestClient_EnvironmentReservedHeader(t *testing.T) {
	isolateHeaderEnvironment(t)
	t.Setenv(api.EnvVaultHeaders, `{"X-Vault-Test":"value"}`)

	client, err := (&BaseCommand{}).Client()
	require.Nil(t, client)
	require.ErrorContains(t, err, "BAO_HEADERS contains a header name with reserved prefix")
}
