// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
)

type SealStatusResponse struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Nonce       string `json:"nonce"`
}

type NamespaceUnsealRequest struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

func (c *Sys) NamespaceSealStatus(namespacePath string) (*SealStatusResponse, error) {
	return c.NamespaceSealStatusWithContext(context.Background(), namespacePath)
}

func (c *Sys) NamespaceSealStatusWithContext(ctx context.Context, namespacePath string) (*SealStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/seal-status", namespacePath))
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *SealStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceSeal(namespacePath string) error {
	return c.NamespaceSealWithContext(context.Background(), namespacePath)
}

func (c *Sys) NamespaceSealWithContext(ctx context.Context, namespacePath string) error {
	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/seal", namespacePath))

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	_, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (c *Sys) NamespaceUnseal(req NamespaceUnsealRequest) (*SealStatusResponse, error) {
	return c.NamespaceUnsealWithContext(context.Background(), req)
}

func (c *Sys) NamespaceUnsealWithContext(ctx context.Context, req NamespaceUnsealRequest) (*SealStatusResponse, error) {
	body := map[string]interface{}{"key": req.Key, "reset": req.Reset}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/unseal", req.Name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *SealStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}
