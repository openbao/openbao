// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
)

type CreateNamespaceRequest struct {
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

func (c *Sys) CreateNamespace(name string) (*CreateNamespaceResponse, error) {
	return c.CreateNamespaceWithContext(context.Background(), name, &CreateNamespaceRequest{})
}

func (c *Sys) CreateNamespaceWithOptions(name string, req *CreateNamespaceRequest) (*CreateNamespaceResponse, error) {
	return c.CreateNamespaceWithContext(context.Background(), name, req)
}

func (c *Sys) CreateNamespaceWithContext(ctx context.Context, name string, req *CreateNamespaceRequest) (*CreateNamespaceResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{"custom_metadata": req.CustomMetadata, "seals": req.Seals}
	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()
	var result struct {
		Data *CreateNamespaceResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

// ----- Sealing/Unsealing -----

type NamespaceSealStatusResponse struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Nonce       string `json:"nonce"`
}

type UnsealNamespaceRequest struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

func (c *Sys) NamespaceSealStatus(name string) (*NamespaceSealStatusResponse, error) {
	return c.NamespaceSealStatusWithContext(context.Background(), name)
}

func (c *Sys) NamespaceSealStatusWithContext(ctx context.Context, name string) (*NamespaceSealStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/seal-status", name))
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *NamespaceSealStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) SealNamespace(name string) error {
	return c.SealNamespaceWithContext(context.Background(), name)
}

func (c *Sys) SealNamespaceWithContext(ctx context.Context, name string) error {
	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/seal", name))

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	_, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (c *Sys) UnsealNamespace(req *UnsealNamespaceRequest) (*NamespaceSealStatusResponse, error) {
	return c.UnsealNamespaceWithContext(context.Background(), req)
}

func (c *Sys) UnsealNamespaceWithContext(ctx context.Context, req *UnsealNamespaceRequest) (*NamespaceSealStatusResponse, error) {
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

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *NamespaceSealStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

// ----- Root token generation -----

func (c *Sys) NamespaceGenerateRootStatus(name string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootStatusWithContext(context.Background(), name)
}

func (c *Sys) NamespaceGenerateRootStatusWithContext(ctx context.Context, name string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}

func (c *Sys) NamespaceGenerateRootInit(otp, pgpKey, name string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootInitWithContext(context.Background(), otp, pgpKey, name)
}

func (c *Sys) NamespaceGenerateRootInitWithContext(ctx context.Context, otp, pgpKey, name string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"otp":     otp,
		"pgp_key": pgpKey,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}

func (c *Sys) NamespaceGenerateRootCancel(name string) error {
	return c.NamespaceGenerateRootCancelWithContext(context.Background(), name)
}

func (c *Sys) NamespaceGenerateRootCancelWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/attempt", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) NamespaceGenerateRootUpdate(shard, nonce, name string) (*GenerateRootStatusResponse, error) {
	return c.NamespaceGenerateRootUpdateWithContext(context.Background(), shard, nonce, name)
}

func (c *Sys) NamespaceGenerateRootUpdateWithContext(ctx context.Context, shard, nonce, name string) (*GenerateRootStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/generate-root/update", name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data GenerateRootStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}
