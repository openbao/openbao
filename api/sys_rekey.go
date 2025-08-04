// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

// Deprecated: use RotateRootStatus instead.
func (c *Sys) RekeyStatus() (*RotateStatusResponse, error) {
	return c.RekeyStatusWithContext(context.Background())
}

// Deprecated: use RotateRootStatusWithContext instead.
func (c *Sys) RekeyStatusWithContext(ctx context.Context) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRecoveryStatus instead.
func (c *Sys) RekeyRecoveryKeyStatus() (*RotateStatusResponse, error) {
	return c.RekeyRecoveryKeyStatusWithContext(context.Background())
}

// Deprecated: use RotateRecoveryStatusWithContext instead.
func (c *Sys) RekeyRecoveryKeyStatusWithContext(ctx context.Context) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey-recovery-key/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRootVerificationStatus instead.
func (c *Sys) RekeyVerificationStatus() (*RotateVerificationStatusResponse, error) {
	return c.RekeyVerificationStatusWithContext(context.Background())
}

// Deprecated: use RotateRootVerificationStatusWithContext instead.
func (c *Sys) RekeyVerificationStatusWithContext(ctx context.Context) (*RotateVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateVerificationStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRecoveryVerificationStatus instead.
func (c *Sys) RekeyRecoveryKeyVerificationStatus() (*RotateVerificationStatusResponse, error) {
	return c.RekeyRecoveryKeyVerificationStatusWithContext(context.Background())
}

// Deprecated: use RotateRecoveryVerificationStatusWithContext instead.
func (c *Sys) RekeyRecoveryKeyVerificationStatusWithContext(ctx context.Context) (*RotateVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey-recovery-key/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateVerificationStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRootInit instead.
func (c *Sys) RekeyInit(config *RotateInitRequest) (*RotateStatusResponse, error) {
	return c.RekeyInitWithContext(context.Background(), config)
}

// Deprecated: use RotateRootInitWithContext instead.
func (c *Sys) RekeyInitWithContext(ctx context.Context, config *RotateInitRequest) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey/init")
	if err := r.SetJSONBody(config); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRecoveryInit instead.
func (c *Sys) RekeyRecoveryKeyInit(config *RotateInitRequest) (*RotateStatusResponse, error) {
	return c.RekeyRecoveryKeyInitWithContext(context.Background(), config)
}

// Deprecated: use RotateRecoveryInitWithContext instead.
func (c *Sys) RekeyRecoveryKeyInitWithContext(ctx context.Context, config *RotateInitRequest) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey-recovery-key/init")
	if err := r.SetJSONBody(config); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRootCancel instead.
func (c *Sys) RekeyCancel() error {
	return c.RekeyCancelWithContext(context.Background())
}

// Deprecated: use RotateRootCancelWithContext instead.
func (c *Sys) RekeyCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// Deprecated: use RotateRecoveryCancel instead.
func (c *Sys) RekeyRecoveryKeyCancel() error {
	return c.RekeyRecoveryKeyCancelWithContext(context.Background())
}

// Deprecated: use RotateRecoveryCancelWithContext instead.
func (c *Sys) RekeyRecoveryKeyCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey-recovery-key/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// Deprecated: use RotateRootVerificationCancel instead.
func (c *Sys) RekeyVerificationCancel() error {
	return c.RekeyVerificationCancelWithContext(context.Background())
}

// Deprecated: use RotateRootVerificationCancelWithContext instead.
func (c *Sys) RekeyVerificationCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// Deprecated: use RotateRecoveryVerificationCancel instead.
func (c *Sys) RekeyRecoveryKeyVerificationCancel() error {
	return c.RekeyRecoveryKeyVerificationCancelWithContext(context.Background())
}

// Deprecated: use RotateRecoveryVerificationCancelWithContext instead.
func (c *Sys) RekeyRecoveryKeyVerificationCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey-recovery-key/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// Deprecated: use RotateRootUpdate instead.
func (c *Sys) RekeyUpdate(shard, nonce string) (*RotateUpdateResponse, error) {
	return c.RekeyUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateRootUpdateWithContext instead.
func (c *Sys) RekeyUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey/update")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRecoveryUpdate instead.
func (c *Sys) RekeyRecoveryKeyUpdate(shard, nonce string) (*RotateUpdateResponse, error) {
	return c.RekeyRecoveryKeyUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateRecoveryUpdateWithContext instead.
func (c *Sys) RekeyRecoveryKeyUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey-recovery-key/update")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRootRetrieveBackup instead.
func (c *Sys) RekeyRetrieveBackup() (*RotateRetrieveResponse, error) {
	return c.RekeyRetrieveBackupWithContext(context.Background())
}

// Deprecated: use RotateRootRetrieveBackupWithContext instead.
func (c *Sys) RekeyRetrieveBackupWithContext(ctx context.Context) (*RotateRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	var result RotateRetrieveResponse
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

// Deprecated: use RotateRecoveryRetrieveBackup instead.
func (c *Sys) RekeyRetrieveRecoveryBackup() (*RotateRetrieveResponse, error) {
	return c.RekeyRetrieveRecoveryBackupWithContext(context.Background())
}

// Deprecated: use RotateRecoveryRetrieveBackupWithContext instead.
func (c *Sys) RekeyRetrieveRecoveryBackupWithContext(ctx context.Context) (*RotateRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/recovery-key-backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	var result RotateRetrieveResponse
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

// Deprecated: use RotateRootDeleteBackup instead.
func (c *Sys) RekeyDeleteBackup() error {
	return c.RekeyDeleteBackupWithContext(context.Background())
}

// Deprecated: use RotateRootDeleteBackupWithContext instead.
func (c *Sys) RekeyDeleteBackupWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey/backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}

	return err
}

// Deprecated: use RotateRecoveryDeleteBackup instead.
func (c *Sys) RekeyDeleteRecoveryBackup() error {
	return c.RekeyDeleteRecoveryBackupWithContext(context.Background())
}

// Deprecated: use RotateRecoveryDeleteBackupWithContext instead.
func (c *Sys) RekeyDeleteRecoveryBackupWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rekey/recovery-key-backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}

	return err
}

// Deprecated: use RotateRootVerificationUpdate instead.
func (c *Sys) RekeyVerificationUpdate(shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	return c.RekeyVerificationUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateRootVerificationUpdateWithContext instead.
func (c *Sys) RekeyVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey/verify")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateVerificationUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRecoveryVerificationUpdate instead.
func (c *Sys) RekeyRecoveryKeyVerificationUpdate(shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	return c.RekeyRecoveryKeyVerificationUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateRecoveryVerificationUpdateWithContext instead.
func (c *Sys) RekeyRecoveryKeyVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rekey-recovery-key/verify")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RotateVerificationUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}
