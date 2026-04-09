// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSysNamespaces_ListNamespaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces" {
			t.Fatalf("expected /v1/sys/namespaces, got %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"admin/": map[string]interface{}{
				"id":             "some-uuid",
				"path":           "admin/",
				"custom_metadata": map[string]string{"team": "ops"},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": resp,
		})
	}))
	defer ts.Close()

	client, err := NewClient(&Config{Address: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	namespaces, err := client.Sys().ListNamespaces()
	if err != nil {
		t.Fatal(err)
	}

	if len(namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(namespaces))
	}

	ns, ok := namespaces["admin/"]
	if !ok {
		t.Fatal("expected admin/ namespace")
	}
	if ns.ID != "some-uuid" {
		t.Fatalf("expected ID some-uuid, got %s", ns.ID)
	}
	if ns.Path != "admin/" {
		t.Fatalf("expected path admin/, got %s", ns.Path)
	}
}

func TestSysNamespaces_GetNamespace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces/admin" {
			t.Fatalf("expected /v1/sys/namespaces/admin, got %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"id":              "some-uuid",
			"path":            "admin/",
			"custom_metadata": map[string]string{"team": "ops"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": resp,
		})
	}))
	defer ts.Close()

	client, err := NewClient(&Config{Address: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	ns, err := client.Sys().GetNamespace("admin")
	if err != nil {
		t.Fatal(err)
	}

	if ns.ID != "some-uuid" {
		t.Fatalf("expected ID some-uuid, got %s", ns.ID)
	}
}

func TestSysNamespaces_CreateNamespace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces/admin" {
			t.Fatalf("expected /v1/sys/namespaces/admin, got %s", r.URL.Path)
		}

		var input NamespaceInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.CustomMetadata["team"] != "ops" {
			t.Fatalf("expected custom_metadata team=ops, got %v", input.CustomMetadata)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client, err := NewClient(&Config{Address: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().CreateNamespace("admin", &NamespaceInput{
		CustomMetadata: map[string]string{"team": "ops"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSysNamespaces_DeleteNamespace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces/admin" {
			t.Fatalf("expected /v1/sys/namespaces/admin, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client, err := NewClient(&Config{Address: ts.URL})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().DeleteNamespace("admin")
	if err != nil {
		t.Fatal(err)
	}
}
