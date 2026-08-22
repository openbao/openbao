// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

func (c *Sys) ListWorkflows() ([]string, error) {
	return c.ListWorkflowsWithContext(context.Background())
}

func (c *Sys) ListWorkflowsWithContext(ctx context.Context) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest("LIST", "/v1/sys/workflows/manage")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	if resp != nil && resp.StatusCode == 404 {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	var results []string
	err = mapstructure.Decode(secret.Data["keys"], &results)
	if err != nil {
		return nil, err
	}

	return results, err
}

type GetWorkflowResponse struct {
	AllowUnauthenticated bool   `json:"allow_unauthenticated"`
	CasRequired          bool   `json:"cas_required"`
	Description          string `json:"description"`
	Path                 string `json:"path"`
	Workflow             string `json:"workflow"`
	Version              int    `json:"version"`
}

func (c *Sys) GetWorkflow(path string) (*GetWorkflowResponse, error) {
	return c.GetWorkflowWithContext(context.Background(), path)
}

func (c *Sys) GetWorkflowWithContext(ctx context.Context, path string) (*GetWorkflowResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/workflows/manage/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *GetWorkflowResponse
	}
	err = resp.DecodeJSON(&result)
	if err != nil {
		return nil, err
	}
	return result.Data, err
}

type PutWorkflowInput struct {
	Workflow             string `json:"workflow"`
	Description          string `json:"description,omitempty"`
	AllowUnauthenticated bool   `json:"allow_unauthenticated,omitempty"`
	CASRequired          bool   `json:"cas_required,omitempty"`
	CAS                  *int   `json:"cas,omitempty"`
}

func (c *Sys) PutWorkflow(path string, input PutWorkflowInput) (*GetWorkflowResponse, error) {
	return c.PutWorkflowWithContext(context.Background(), path, input)
}

func (c *Sys) PutWorkflowWithContext(ctx context.Context, path string, input PutWorkflowInput) (*GetWorkflowResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/workflows/manage/%s", path))
	if err := r.SetJSONBody(input); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *GetWorkflowResponse
	}
	err = resp.DecodeJSON(&result)
	if err != nil {
		return nil, err
	}
	return result.Data, err
}

func (c *Sys) DeleteWorkflow(path string) error {
	return c.DeleteWorkflowWithContext(context.Background(), path)
}

func (c *Sys) DeleteWorkflowWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/workflows/manage/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	return err
}

func (c *Sys) CallWorkflow(path string, data map[string]any) (*Secret, error) {
	return c.CallWorkflowWithContext(context.Background(), path, data)
}

func (c *Sys) CallWorkflowWithContext(ctx context.Context, path string, data map[string]any) (*Secret, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/workflows/execute/%s", path))
	if err := r.SetJSONBody(data); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}

	return secret, nil
}
