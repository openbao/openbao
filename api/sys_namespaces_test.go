// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"
)

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
