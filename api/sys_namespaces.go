// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
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

// ----- Key status retrieval -----

func (c *Sys) NamespaceKeyStatus(name string) (*KeyStatus, error) {
	return c.NamespaceKeyStatusWithContext(context.Background(), name)
}

func (c *Sys) NamespaceKeyStatusWithContext(ctx context.Context, name string) (*KeyStatus, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/key-status", name))
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data KeyStatus
	}
	err = resp.DecodeJSON(&result)
	return &result.Data, err
}

// ----- Keyring rotation -----

func (c *Sys) NamespaceRotateKeyring(name string) error {
	return c.NamespaceRotateKeyringWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateKeyringWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/keyring", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ----- Unseal keys rotation -----

func (c *Sys) NamespaceRotateRootStatus(name string) (*RotateStatusResponse, error) {
	return c.NamespaceRotateRootStatusWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootStatusWithContext(ctx context.Context, name string) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/init", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceRotateRootInit(name string, config *RotateInitRequest) (*RotateStatusResponse, error) {
	return c.NamespaceRotateRootInitWithContext(context.Background(), name, config)
}

func (c *Sys) NamespaceRotateRootInitWithContext(ctx context.Context, name string, config *RotateInitRequest) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/init", name))
	if err := r.SetJSONBody(config); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceRotateRootCancel(name string) error {
	return c.NamespaceRotateRootCancelWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootCancelWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/init", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) NamespaceRotateRootUpdate(name, shard, nonce string) (*RotateUpdateResponse, error) {
	return c.NamespaceRotateRootUpdateWithContext(context.Background(), name, shard, nonce)
}

func (c *Sys) NamespaceRotateRootUpdateWithContext(ctx context.Context, name, shard, nonce string) (*RotateUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/update", name))
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
		Data *RotateUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceRotateRootRetrieveBackup(name string) (*RotateRetrieveResponse, error) {
	return c.NamespaceRotateRootRetrieveBackupWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootRetrieveBackupWithContext(ctx context.Context, name string) (*RotateRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/backup", name))
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	var result RotateRetrieveResponse
	if err = mapstructure.Decode(secret.Data, &result); err != nil {
		return nil, err
	}

	return &result, err
}

func (c *Sys) NamespaceRotateRootDeleteBackup(name string) error {
	return c.NamespaceRotateRootDeleteBackupWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootDeleteBackupWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/backup", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) NamespaceRotateRootVerificationStatus(name string) (*RotateVerificationStatusResponse, error) {
	return c.NamespaceRotateRootVerificationStatusWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootVerificationStatusWithContext(ctx context.Context, name string) (*RotateVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/verify", name))
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *RotateVerificationStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceRotateRootVerificationUpdate(name, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	return c.NamespaceRotateRootVerificationUpdateWithContext(context.Background(), name, shard, nonce)
}

func (c *Sys) NamespaceRotateRootVerificationUpdateWithContext(ctx context.Context, name, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/verify", name))
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
		Data *RotateVerificationUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) NamespaceRotateRootVerificationCancel(name string) error {
	return c.NamespaceRotateRootVerificationCancelWithContext(context.Background(), name)
}

func (c *Sys) NamespaceRotateRootVerificationCancelWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s/rotate/root/verify", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
