// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

// ListNamespaces lists all available namespaces.
func (c *Sys) ListNamespaces() (map[string]*Namespace, error) {
	return c.ListNamespacesWithContext(context.Background())
}

// ListNamespacesWithContext lists all available namespaces.
func (c *Sys) ListNamespacesWithContext(ctx context.Context) (map[string]*Namespace, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/namespaces")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	namespaces := map[string]*Namespace{}
	err = mapstructure.Decode(secret.Data, &namespaces)
	if err != nil {
		return nil, err
	}

	return namespaces, nil
}

// GetNamespace retrieves details about a specific namespace at the given path.
func (c *Sys) GetNamespace(path string) (*Namespace, error) {
	return c.GetNamespaceWithContext(context.Background(), path)
}

// GetNamespaceWithContext retrieves details about a specific namespace at the given path.
func (c *Sys) GetNamespaceWithContext(ctx context.Context, path string) (*Namespace, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	var result Namespace
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateNamespace creates a new namespace at the given path.
func (c *Sys) CreateNamespace(path string, ns *NamespaceInput) error {
	return c.CreateNamespaceWithContext(context.Background(), path, ns)
}

// CreateNamespaceWithContext creates a new namespace at the given path.
func (c *Sys) CreateNamespaceWithContext(ctx context.Context, path string, ns *NamespaceInput) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", path))
	if err := r.SetJSONBody(ns); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	return nil
}

// DeleteNamespace deletes the namespace at the given path.
func (c *Sys) DeleteNamespace(path string) error {
	return c.DeleteNamespaceWithContext(context.Background(), path)
}

// DeleteNamespaceWithContext deletes the namespace at the given path.
func (c *Sys) DeleteNamespaceWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	return nil
}

// NamespaceInput represents the input for creating or updating a namespace.
type NamespaceInput struct {
	// CustomMetadata is metadata for the namespace that is persisted to storage.
	CustomMetadata map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
}

// Namespace represents a namespace in OpenBao.
type Namespace struct {
	// ID is the unique identifier of the namespace.
	ID string `json:"id" mapstructure:"id"`
	// Path is the path of the namespace.
	Path string `json:"path" mapstructure:"path"`
	// CustomMetadata is the metadata associated with the namespace.
	CustomMetadata map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
}
