// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

// Deprecated: use RotateStatus (recovery=false) instead.
func (c *Sys) RekeyStatus() (*RekeyStatusResponse, error) {
	return c.RekeyStatusWithContext(context.Background())
}

// Deprecated: use RotateStatusWithContext (recovery=false) instead.
func (c *Sys) RekeyStatusWithContext(ctx context.Context) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RekeyStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateStatus (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyStatus() (*RekeyStatusResponse, error) {
	return c.RekeyRecoveryKeyStatusWithContext(context.Background())
}

// Deprecated: use RotateStatusWithContext (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyStatusWithContext(ctx context.Context) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey-recovery-key/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RekeyStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateVerificationStatus (recovery=false) instead.
func (c *Sys) RekeyVerificationStatus() (*RekeyVerificationStatusResponse, error) {
	return c.RekeyVerificationStatusWithContext(context.Background())
}

// Deprecated: use RotateVerificationStatusWithContext (recovery=false) instead.
func (c *Sys) RekeyVerificationStatusWithContext(ctx context.Context) (*RekeyVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RekeyVerificationStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateVerificationStatus (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyVerificationStatus() (*RekeyVerificationStatusResponse, error) {
	return c.RekeyRecoveryKeyVerificationStatusWithContext(context.Background())
}

// Deprecated: use RotateVerificationStatusWithContext (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyVerificationStatusWithContext(ctx context.Context) (*RekeyVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rekey-recovery-key/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RekeyVerificationStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateInit (recovery=false) instead.
func (c *Sys) RekeyInit(config *RekeyInitRequest) (*RekeyStatusResponse, error) {
	return c.RekeyInitWithContext(context.Background(), config)
}

// Deprecated: use RotateInitWithContext (recovery=false) instead.
func (c *Sys) RekeyInitWithContext(ctx context.Context, config *RekeyInitRequest) (*RekeyStatusResponse, error) {
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

	var result RekeyStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateInit (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyInit(config *RekeyInitRequest) (*RekeyStatusResponse, error) {
	return c.RekeyRecoveryKeyInitWithContext(context.Background(), config)
}

// Deprecated: use RotateInitWithContext (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyInitWithContext(ctx context.Context, config *RekeyInitRequest) (*RekeyStatusResponse, error) {
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

	var result RekeyStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateCancel (recovery=false) instead.
func (c *Sys) RekeyCancel() error {
	return c.RekeyCancelWithContext(context.Background())
}

// Deprecated: use RotateCancelWithContext (recovery=false) instead.
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

// Deprecated: use RotateCancel (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyCancel() error {
	return c.RekeyRecoveryKeyCancelWithContext(context.Background())
}

// Deprecated: use RotateCancelWithContext (recovery=true) instead.
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

// Deprecated: use RotateVerificationCancel (recovery=false) instead.
func (c *Sys) RekeyVerificationCancel() error {
	return c.RekeyVerificationCancelWithContext(context.Background())
}

// Deprecated: use RotateVerificationCancelWithContext (recovery=false) instead.
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

// Deprecated: use RotateVerificationCancel (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyVerificationCancel() error {
	return c.RekeyRecoveryKeyVerificationCancelWithContext(context.Background())
}

// Deprecated: use RotateVerificationCancelWithContext (recovery=true) instead.
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

// Deprecated: use RotateUpdate (recovery=false) instead.
func (c *Sys) RekeyUpdate(shard, nonce string) (*RekeyUpdateResponse, error) {
	return c.RekeyUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateUpdateWithContext (recovery=false) instead.
func (c *Sys) RekeyUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyUpdateResponse, error) {
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

	var result RekeyUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateUpdate (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyUpdate(shard, nonce string) (*RekeyUpdateResponse, error) {
	return c.RekeyRecoveryKeyUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateUpdateWithContext (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyUpdateResponse, error) {
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

	var result RekeyUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateRetrieveBackup (recovery=false) instead.
func (c *Sys) RekeyRetrieveBackup() (*RekeyRetrieveResponse, error) {
	return c.RekeyRetrieveBackupWithContext(context.Background())
}

// Deprecated: use RotateRetrieveBackupWithContext (recovery=false) instead.
func (c *Sys) RekeyRetrieveBackupWithContext(ctx context.Context) (*RekeyRetrieveResponse, error) {
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

	var result RekeyRetrieveResponse
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

// Deprecated: use RotateRetrieveBackup (recovery=true) instead.
func (c *Sys) RekeyRetrieveRecoveryBackup() (*RekeyRetrieveResponse, error) {
	return c.RekeyRetrieveRecoveryBackupWithContext(context.Background())
}

// Deprecated: use RotateRetrieveBackupWithContext (recovery=true) instead.
func (c *Sys) RekeyRetrieveRecoveryBackupWithContext(ctx context.Context) (*RekeyRetrieveResponse, error) {
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

	var result RekeyRetrieveResponse
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

// Deprecated: use RotateDeleteBackup (recovery=false) instead.
func (c *Sys) RekeyDeleteBackup() error {
	return c.RekeyDeleteBackupWithContext(context.Background())
}

// Deprecated: use RotateDeleteBackupWithContext (recovery=false) instead.
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

// Deprecated: use RotateDeleteBackup (recovery=true) instead.
func (c *Sys) RekeyDeleteRecoveryBackup() error {
	return c.RekeyDeleteRecoveryBackupWithContext(context.Background())
}

// Deprecated: use RotateDeleteBackupWithContext (recovery=true) instead.
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

// Deprecated: use RotateVerificationUpdate (recovery=false) instead.
func (c *Sys) RekeyVerificationUpdate(shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
	return c.RekeyVerificationUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateVerificationUpdateWithContext (recovery=false) instead.
func (c *Sys) RekeyVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
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

	var result RekeyVerificationUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

// Deprecated: use RotateVerificationUpdate (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyVerificationUpdate(shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
	return c.RekeyRecoveryKeyVerificationUpdateWithContext(context.Background(), shard, nonce)
}

// Deprecated: use RotateVerificationUpdateWithContext (recovery=true) instead.
func (c *Sys) RekeyRecoveryKeyVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
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

	var result RekeyVerificationUpdateResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

type RekeyInitRequest struct {
	SecretShares        int      `json:"secret_shares"`
	SecretThreshold     int      `json:"secret_threshold"`
	StoredShares        int      `json:"stored_shares"`
	PGPKeys             []string `json:"pgp_keys"`
	Backup              bool
	RequireVerification bool `json:"require_verification"`
}

type RekeyStatusResponse struct {
	Nonce                string   `json:"nonce"`
	Started              bool     `json:"started"`
	T                    int      `json:"t"`
	N                    int      `json:"n"`
	Progress             int      `json:"progress"`
	Required             int      `json:"required"`
	PGPFingerprints      []string `json:"pgp_fingerprints"`
	Backup               bool     `json:"backup"`
	VerificationRequired bool     `json:"verification_required"`
	VerificationNonce    string   `json:"verification_nonce"`
}

type RekeyUpdateResponse struct {
	Nonce                string   `json:"nonce"`
	Complete             bool     `json:"complete"`
	Keys                 []string `json:"keys"`
	KeysB64              []string `json:"keys_base64"`
	PGPFingerprints      []string `json:"pgp_fingerprints"`
	Backup               bool     `json:"backup"`
	VerificationRequired bool     `json:"verification_required"`
	VerificationNonce    string   `json:"verification_nonce,omitempty"`
}

type RekeyRetrieveResponse struct {
	Nonce   string              `json:"nonce" mapstructure:"nonce"`
	Keys    map[string][]string `json:"keys" mapstructure:"keys"`
	KeysB64 map[string][]string `json:"keys_base64" mapstructure:"keys_base64"`
}

type RekeyVerificationStatusResponse struct {
	Nonce    string `json:"nonce"`
	Started  bool   `json:"started"`
	T        int    `json:"t"`
	N        int    `json:"n"`
	Progress int    `json:"progress"`
}

type RekeyVerificationUpdateResponse struct {
	Nonce    string `json:"nonce"`
	Complete bool   `json:"complete"`
}
