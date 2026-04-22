// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// mockNamespaceHandler returns an HTTP handler that writes the given body.
func mockNamespaceHandler(body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}
}

func TestCreateNamespaceValidation(t *testing.T) {
	cfg := DefaultConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Sys().CreateNamespace("", nil); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

func TestPatchNamespaceValidation(t *testing.T) {
	cfg := DefaultConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Sys().PatchNamespace("", nil); err == nil {
		t.Error("expected error for empty path, got nil")
	}
	if _, err := client.Sys().PatchNamespace("ns1", nil); err == nil {
		t.Error("expected error for nil input, got nil")
	}
}

func TestReadNamespaceValidation(t *testing.T) {
	cfg := DefaultConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Sys().ReadNamespace(""); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

func TestDeleteNamespaceValidation(t *testing.T) {
	cfg := DefaultConfig()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Sys().DeleteNamespace(""); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

func TestCreateNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		input    CreateNamespaceInput
		expected CreateNamespaceResponse
	}{
		"namespace with custom metadata": {
			body: createNamespaceResponse,
			input: CreateNamespaceInput{
				CustomMetadata: map[string]string{"env": "prod"},
			},
			expected: CreateNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        false,
				Locked:         false,
				CustomMetadata: map[string]string{"env": "prod"},
				KeyShares:      nil,
			},
		},
		"namespace without custom metadata": {
			body:  createNamespaceResponseNoMetadata,
			input: CreateNamespaceInput{},
			expected: CreateNamespaceResponse{
				UUID:           "def456",
				ID:             "ns2",
				Path:           "ns2/",
				Tainted:        false,
				Locked:         false,
				CustomMetadata: nil,
				KeyShares:      nil,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(mockNamespaceHandler(tc.body)))
			defer mockServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Sys().CreateNamespaceWithContext(t.Context(), "ns1", &tc.input)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, *resp) {
				t.Errorf("expected: %#v\ngot: %#v", tc.expected, *resp)
			}
		})
	}
}

func TestReadNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		expected ReadNamespaceResponse
	}{
		"existing namespace": {
			body: readNamespaceResponse,
			expected: ReadNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        false,
				Locked:         false,
				CustomMetadata: map[string]string{"env": "prod"},
				KeyShares:      nil,
			},
		},
		"tainted namespace": {
			body: readNamespaceTaintedResponse,
			expected: ReadNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        true,
				Locked:         false,
				CustomMetadata: nil,
				KeyShares:      nil,
			},
		},
		"locked namespace": {
			body: readNamespaceLockedResponse,
			expected: ReadNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        false,
				Locked:         true,
				CustomMetadata: nil,
				KeyShares:      nil,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(mockNamespaceHandler(tc.body)))
			defer mockServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Sys().ReadNamespaceWithContext(t.Context(), "ns1")
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, *resp) {
				t.Errorf("expected: %#v\ngot: %#v", tc.expected, *resp)
			}
		})
	}
}

func TestPatchNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		input    PatchNamespaceInput
		expected PatchNamespaceResponse
	}{
		"add metadata key": {
			body: patchNamespaceResponse,
			input: PatchNamespaceInput{
				CustomMetadata: map[string]interface{}{"env": "staging"},
			},
			expected: PatchNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        false,
				Locked:         false,
				CustomMetadata: map[string]string{"env": "staging"},
				KeyShares:      nil,
			},
		},
		"remove metadata key": {
			body: patchNamespaceResponse,
			input: PatchNamespaceInput{
				CustomMetadata: map[string]interface{}{"env": nil},
			},
			expected: PatchNamespaceResponse{
				UUID:           "abc123",
				ID:             "ns1",
				Path:           "ns1/",
				Tainted:        false,
				Locked:         false,
				CustomMetadata: map[string]string{"env": "staging"},
				KeyShares:      nil,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(mockNamespaceHandler(tc.body)))
			defer mockServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Sys().PatchNamespaceWithContext(t.Context(), "ns1", &tc.input)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, *resp) {
				t.Errorf("expected: %#v\ngot: %#v", tc.expected, *resp)
			}
		})
	}
}

func TestDeleteNamespace(t *testing.T) {
	for name, tc := range map[string]struct {
		body           string
		expectedStatus string
	}{
		"successful delete": {
			body:           deleteNamespaceResponse,
			expectedStatus: "deleting",
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(mockNamespaceHandler(tc.body)))
			defer mockServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Sys().DeleteNamespaceWithContext(t.Context(), "ns1")
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if resp.Status != tc.expectedStatus {
				t.Errorf("expected status %q but got %q", tc.expectedStatus, resp.Status)
			}
		})
	}
}

func TestListNamespaces(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		expected map[string]ReadNamespaceResponse
	}{
		"multiple namespaces": {
			body: listNamespacesResponse,
			expected: map[string]ReadNamespaceResponse{
				"ns1/": {
					UUID:           "abc123",
					ID:             "ns1",
					Path:           "ns1/",
					Tainted:        false,
					Locked:         false,
					CustomMetadata: map[string]string{"env": "prod"},
				},
				"ns2/": {
					UUID:           "def456",
					ID:             "ns2",
					Path:           "ns2/",
					Tainted:        false,
					Locked:         false,
					CustomMetadata: nil,
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(mockNamespaceHandler(tc.body)))
			defer mockServer.Close()

			cfg := DefaultConfig()
			cfg.Address = mockServer.URL
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Sys().ListNamespacesWithContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expected, resp) {
				t.Errorf("expected: %#v\ngot: %#v", tc.expected, resp)
			}
		})
	}
}

const createNamespaceResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "abc123",
		"id": "ns1",
		"path": "ns1/",
		"tainted": false,
		"locked": false,
		"custom_metadata": {"env": "prod"}
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const createNamespaceResponseNoMetadata = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "def456",
		"id": "ns2",
		"path": "ns2/",
		"tainted": false,
		"locked": false,
		"custom_metadata": null
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const readNamespaceResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "abc123",
		"id": "ns1",
		"path": "ns1/",
		"tainted": false,
		"locked": false,
		"custom_metadata": {"env": "prod"}
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const readNamespaceTaintedResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "abc123",
		"id": "ns1",
		"path": "ns1/",
		"tainted": true,
		"locked": false,
		"custom_metadata": null
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const readNamespaceLockedResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "abc123",
		"id": "ns1",
		"path": "ns1/",
		"tainted": false,
		"locked": true,
		"custom_metadata": null
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const patchNamespaceResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"uuid": "abc123",
		"id": "ns1",
		"path": "ns1/",
		"tainted": false,
		"locked": false,
		"custom_metadata": {"env": "staging"}
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const deleteNamespaceResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"status": "deleting"
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

const listNamespacesResponse = `{
	"request_id": "abc",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"keys": ["ns1/", "ns2/"],
		"key_info": {
			"ns1/": {
				"uuid": "abc123",
				"id": "ns1",
				"path": "ns1/",
				"tainted": false,
				"locked": false,
				"custom_metadata": {"env": "prod"}
			},
			"ns2/": {
				"uuid": "def456",
				"id": "ns2",
				"path": "ns2/",
				"tainted": false,
				"locked": false,
				"custom_metadata": null
			}
		}
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`
