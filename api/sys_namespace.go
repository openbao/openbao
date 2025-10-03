// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
)

type CreateNamespaceRequest struct {
	Name           string                   `json:"name"`
	CustomMetadata map[string]string        `json:"custom_metadata"`
	Seals          []map[string]interface{} `json:"seals"`
}

type CreateNamespaceResponse struct {
	UUID           string              `json:"uuid"`
	ID             string              `json:"id"`
	Path           string              `json:"path"`
	Tainted        bool                `json:"tainted"`
	Locked         bool                `json:"locked"`
	CustomMetadata map[string]string   `json:"custom_metadata"`
	KeyShares      map[string][]string `json:"key_shares,omitempty"`
}

func (c *Sys) CreateNamespace(req *CreateNamespaceRequest) (*CreateNamespaceResponse, error) {
	return c.CreateNamespaceWithContext(context.Background(), req)
}

func (c *Sys) CreateNamespaceWithContext(ctx context.Context, req *CreateNamespaceRequest) (*CreateNamespaceResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{"custom_metadata": req.CustomMetadata, "seals": req.Seals}
	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", req.Name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Data *CreateNamespaceResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}
