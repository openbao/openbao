// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Sys) NamespaceGenerateRootStatus(namespacePath string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootStatusWithContext(context.Background(), namespacePath)
}

func (c *Sys) NamespaceGenerateRootStatusWithContext(ctx context.Context, namespacePath string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", namespacePath))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}

func (c *Sys) NamespaceGenerateRootInit(otp, pgpKey, namespacePath string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootInitWithContext(context.Background(), otp, pgpKey, namespacePath)
}

func (c *Sys) NamespaceGenerateRootInitWithContext(ctx context.Context, otp, pgpKey, namespacePath string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"otp":     otp,
		"pgp_key": pgpKey,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", namespacePath))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}

func (c *Sys) NamespaceGenerateRootCancel(namespacePath string) error {
	return c.NamespaceGenerateRootCancelWithContext(context.Background(), namespacePath)
}

func (c *Sys) NamespaceGenerateRootCancelWithContext(ctx context.Context, namespacePath string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", namespacePath))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) NamespaceGenerateRootUpdate(shard, nonce, namespacePath string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootUpdateWithContext(context.Background(), shard, nonce, namespacePath)
}

func (c *Sys) NamespaceGenerateRootUpdateWithContext(ctx context.Context, shard, nonce, namespacePath string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/update", namespacePath))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}
