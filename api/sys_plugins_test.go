// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
)

func TestRegisterPlugin(t *testing.T) {
	mockVaultServer := httptest.NewServer(http.HandlerFunc(mockVaultHandlerRegister))
	defer mockVaultServer.Close()

	cfg := DefaultConfig()
	cfg.Address = mockVaultServer.URL
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().RegisterPluginWithContext(context.Background(), &RegisterPluginInput{
		Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestListPlugins(t *testing.T) {
	mockVaultServer := httptest.NewServer(http.HandlerFunc(mockVaultHandlerList))
	defer mockVaultServer.Close()

	cfg := DefaultConfig()
	cfg.Address = mockVaultServer.URL
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		input           ListPluginsInput
		expectedPlugins map[PluginType][]string
	}{
		"no type specified": {
			input: ListPluginsInput{},
			expectedPlugins: map[PluginType][]string{
				PluginTypeCredential: {"jwt"},
				PluginTypeDatabase:   {"cassandra-database-plugin"},
				PluginTypeSecrets:    {"kv", "pki"},
			},
		},
		"only auth plugins": {
			input: ListPluginsInput{Type: PluginTypeCredential},
			expectedPlugins: map[PluginType][]string{
				PluginTypeCredential: {"jwt"},
			},
		},
		"only database plugins": {
			input: ListPluginsInput{Type: PluginTypeDatabase},
			expectedPlugins: map[PluginType][]string{
				PluginTypeDatabase: {"cassandra-database-plugin"},
			},
		},
		"only secret plugins": {
			input: ListPluginsInput{Type: PluginTypeSecrets},
			expectedPlugins: map[PluginType][]string{
				PluginTypeSecrets: {"kv", "pki"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Sys().ListPluginsWithContext(context.Background(), &tc.input)
			if err != nil {
				t.Fatal(err)
			}

			for pluginType, expected := range tc.expectedPlugins {
				actualPlugins := resp.PluginsByType[pluginType]
				if len(expected) != len(actualPlugins) {
					t.Fatal("Wrong number of plugins", expected, actualPlugins)
				}
				for i := range actualPlugins {
					if expected[i] != actualPlugins[i] {
						t.Fatalf("Expected %q but got %q\n\texpected: %v\n\tactual: %v", expected[i], actualPlugins[i], expected, actualPlugins)
					}
				}

				for _, expectedPlugin := range expected {
					found := false
					for _, plugin := range resp.Details {
						if plugin.Type == pluginType.String() && plugin.Name == expectedPlugin {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected to find %s plugin %s but not found in details: %#v", pluginType.String(), expectedPlugin, resp.Details)
					}
				}
			}

			for _, actual := range resp.Details {
				pluginType, err := ParsePluginType(actual.Type)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(tc.expectedPlugins[pluginType], actual.Name) {
					t.Errorf("Did not expect to find %s in details", actual.Name)
				}
			}
		})
	}
}

func TestGetPlugin(t *testing.T) {
	for name, tc := range map[string]struct {
		version  string
		body     string
		expected GetPluginResponse
	}{
		"builtin": {
			body: getResponse,
			expected: GetPluginResponse{
				Args:              nil,
				Builtin:           true,
				Command:           "",
				Name:              "approle",
				SHA256:            "",
				DeprecationStatus: "supported",
				Version:           "v0.14.0+builtin",
			},
		},
		"external": {
			version: "v1.0.0",
			body:    getResponseExternal,
			expected: GetPluginResponse{
				Args:              []string{},
				Builtin:           false,
				Command:           "approle-plugin",
				Name:              "approle",
				SHA256:            "8ba442dba253803685b05e35ad29dcdebc48dec16774614aa7a4ebe53c1e90e1",
				DeprecationStatus: "",
				Version:           "v1.0.0",
			},
		},
		"old server": {
			body: getResponseOldServerVersion,
			expected: GetPluginResponse{
				Args:              nil,
				Builtin:           true,
				Command:           "",
				Name:              "approle",
				SHA256:            "",
				DeprecationStatus: "",
				Version:           "",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockVaultServer := httptest.NewServer(http.HandlerFunc(mockVaultHandlerInfo(tc.body)))
			defer mockVaultServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockVaultServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			input := GetPluginInput{
				Name: "approle",
				Type: PluginTypeSecrets,
			}
			if tc.version != "" {
				input.Version = tc.version
			}

			info, err := client.Sys().GetPluginWithContext(context.Background(), &input)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, *info) {
				t.Errorf("expected: %#v\ngot: %#v", tc.expected, info)
			}
		})
	}
}

func mockVaultHandlerInfo(body string) func(w http.ResponseWriter, _ *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}
}

const getResponse = `{
    "request_id": "e93d3f93-8e4f-8443-a803-f1c97c495241",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "args": null,
        "builtin": true,
        "command": "",
        "deprecation_status": "supported",
        "name": "approle",
        "sha256": "",
        "version": "v0.14.0+builtin"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}`

const getResponseExternal = `{
    "request_id": "e93d3f93-8e4f-8443-a803-f1c97c495241",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "args": [],
        "builtin": false,
        "command": "approle-plugin",
        "name": "approle",
        "sha256": "8ba442dba253803685b05e35ad29dcdebc48dec16774614aa7a4ebe53c1e90e1",
        "version": "v1.0.0"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}`

const getResponseOldServerVersion = `{
    "request_id": "e93d3f93-8e4f-8443-a803-f1c97c495241",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "args": null,
        "builtin": true,
        "command": "",
        "name": "approle",
        "sha256": ""
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}`

func mockVaultHandlerList(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(listUntypedResponse))
}

const listUntypedResponse = `{
  "request_id": "82601a91-cd7a-718f-feca-f573449cc1bb",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "auth": [
      "jwt"
    ],
    "database": [
      "cassandra-database-plugin"
    ],
    "secret": [
      "kv",
      "pki"
    ],
    "some_other_unexpected_key": [
      {
        "objectKey": "objectValue"
      },
      {
        "arbitraryData": 7
      }
    ],
    "detailed": [
      {
        "type": "auth",
        "name": "jwt",
        "version": "v0.13.0+builtin",
        "builtin": true,
        "deprecation_status": "supported"
      },
      {
        "type": "database",
        "name": "cassandra-database-plugin",
        "version": "v1.13.0+builtin.bao",
        "builtin": true,
        "deprecation_status": "supported"
      },
      {
        "type": "secret",
        "name": "kv",
        "version": "v0.14.0+builtin",
        "builtin": true,
        "deprecation_status": "supported"
      },
      {
        "type": "secret",
        "name": "pki",
        "version": "v0.13.0+builtin",
        "builtin": true,
        "deprecation_status": "supported"
      }
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

func mockVaultHandlerRegister(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(registerResponse))
}

const registerResponse = `{}`
