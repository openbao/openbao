// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

type RotateInitRequest struct {
	SecretShares        int      `json:"secret_shares"`
	SecretThreshold     int      `json:"secret_threshold"`
	StoredShares        int      `json:"stored_shares"`
	PGPKeys             []string `json:"pgp_keys"`
	Backup              bool     `json:"backup"`
	RequireVerification bool     `json:"require_verification"`
}

type RotateStatusResponse struct {
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

type RotateUpdateResponse struct {
	Nonce                string   `json:"nonce"`
	Complete             bool     `json:"complete"`
	Keys                 []string `json:"keys"`
	KeysB64              []string `json:"keys_base64"`
	PGPFingerprints      []string `json:"pgp_fingerprints"`
	Backup               bool     `json:"backup"`
	VerificationRequired bool     `json:"verification_required"`
	VerificationNonce    string   `json:"verification_nonce,omitempty"`
}

type RotateRetrieveResponse struct {
	Nonce   string              `json:"nonce" mapstructure:"nonce"`
	Keys    map[string][]string `json:"keys" mapstructure:"keys"`
	KeysB64 map[string][]string `json:"keys_base64" mapstructure:"keys_base64"`
}

type RotateVerificationStatusResponse struct {
	Nonce    string `json:"nonce"`
	Started  bool   `json:"started"`
	T        int    `json:"t"`
	N        int    `json:"n"`
	Progress int    `json:"progress"`
}

type RotateVerificationUpdateResponse struct {
	Nonce    string `json:"nonce"`
	Complete bool   `json:"complete"`
}

type KeyStatus struct {
	Term        int       `json:"term"`
	InstallTime time.Time `json:"install_time"`
	Encryptions int       `json:"encryptions"`
}

func (c *Sys) RotateRootStatus() (*RotateStatusResponse, error) {
	return c.RotateRootStatusWithContext(context.Background())
}

func (c *Sys) RotateRootStatusWithContext(ctx context.Context) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/root/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryStatus() (*RotateStatusResponse, error) {
	return c.RotateRecoveryStatusWithContext(context.Background())
}

func (c *Sys) RotateRecoveryStatusWithContext(ctx context.Context) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/recovery/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootInit(config *RotateInitRequest) (*RotateStatusResponse, error) {
	return c.RotateRootInitWithContext(context.Background(), config)
}

func (c *Sys) RotateRootInitWithContext(ctx context.Context, config *RotateInitRequest) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/rotate/root/init")
	if err := r.SetJSONBody(config); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryInit(config *RotateInitRequest) (*RotateStatusResponse, error) {
	return c.RotateRecoveryInitWithContext(context.Background(), config)
}

func (c *Sys) RotateRecoveryInitWithContext(ctx context.Context, config *RotateInitRequest) (*RotateStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/rotate/recovery/init")
	if err := r.SetJSONBody(config); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootCancel() error {
	return c.RotateRootCancelWithContext(context.Background())
}

func (c *Sys) RotateRootCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/root/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRecoveryCancel() error {
	return c.RotateRecoveryCancelWithContext(context.Background())
}

func (c *Sys) RotateRecoveryCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/recovery/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRootUpdate(shard, nonce string) (*RotateUpdateResponse, error) {
	return c.RotateRootUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRootUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rotate/root/update")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryUpdate(shard, nonce string) (*RotateUpdateResponse, error) {
	return c.RotateRecoveryUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRecoveryUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rotate/recovery/update")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootRetrieveBackup() (*RotateRetrieveResponse, error) {
	return c.RotateRootRetrieveBackupWithContext(context.Background())
}

func (c *Sys) RotateRootRetrieveBackupWithContext(ctx context.Context) (*RotateRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/root/backup")
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

func (c *Sys) RotateRecoveryRetrieveBackup() (*RotateRetrieveResponse, error) {
	return c.RotateRecoveryRetrieveBackupWithContext(context.Background())
}

func (c *Sys) RotateRecoveryRetrieveBackupWithContext(ctx context.Context) (*RotateRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/recovery/backup")
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

func (c *Sys) RotateRootDeleteBackup() error {
	return c.RotateRootDeleteBackupWithContext(context.Background())
}

func (c *Sys) RotateRootDeleteBackupWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/root/backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRecoveryDeleteBackup() error {
	return c.RotateRecoveryDeleteBackupWithContext(context.Background())
}

func (c *Sys) RotateRecoveryDeleteBackupWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/recovery/backup")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRootVerificationStatus() (*RotateVerificationStatusResponse, error) {
	return c.RotateRootVerificationStatusWithContext(context.Background())
}

func (c *Sys) RotateRootVerificationStatusWithContext(ctx context.Context) (*RotateVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/root/verify")
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateVerificationStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryVerificationStatus() (*RotateVerificationStatusResponse, error) {
	return c.RotateRecoveryVerificationStatusWithContext(context.Background())
}

func (c *Sys) RotateRecoveryVerificationStatusWithContext(ctx context.Context) (*RotateVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/recovery/verify")
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateVerificationStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootVerificationUpdate(shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	return c.RotateRootVerificationUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRootVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rotate/root/verify")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateVerificationUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryVerificationUpdate(shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	return c.RotateRecoveryVerificationUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRecoveryVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RotateVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/rotate/recovery/verify")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RotateVerificationUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootVerificationCancel() error {
	return c.RotateRootVerificationCancelWithContext(context.Background())
}

func (c *Sys) RotateRootVerificationCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/root/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRecoveryVerificationCancel() error {
	return c.RotateRecoveryVerificationCancelWithContext(context.Background())
}

func (c *Sys) RotateRecoveryVerificationCancelWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/rotate/recovery/verify")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Deprecated: use RotateKeyring instead.
func (c *Sys) Rotate() error {
	return c.RotateWithContext(context.Background())
}

// Deprecated: use RotateKeyringWithContext instead.
func (c *Sys) RotateWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/rotate")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateKeyring() error {
	return c.RotateKeyringWithContext(context.Background())
}

func (c *Sys) RotateKeyringWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/rotate/keyring")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateRoot() error {
	return c.RotateRootWithContext(context.Background())
}

func (c *Sys) RotateRootWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/rotate/root")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) KeyStatus() (*KeyStatus, error) {
	return c.KeyStatusWithContext(context.Background())
}

func (c *Sys) KeyStatusWithContext(ctx context.Context) (*KeyStatus, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/key-status")

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

	var result KeyStatus

	termRaw, ok := secret.Data["term"]
	if !ok {
		return nil, errors.New("term not found in response")
	}
	term, ok := termRaw.(json.Number)
	if !ok {
		return nil, errors.New("could not convert term to a number")
	}
	term64, err := term.Int64()
	if err != nil {
		return nil, err
	}
	result.Term = int(term64)

	installTimeRaw, ok := secret.Data["install_time"]
	if !ok {
		return nil, errors.New("install_time not found in response")
	}
	installTimeStr, ok := installTimeRaw.(string)
	if !ok {
		return nil, errors.New("could not convert install_time to a string")
	}
	installTime, err := time.Parse(time.RFC3339Nano, installTimeStr)
	if err != nil {
		return nil, err
	}
	result.InstallTime = installTime

	encryptionsRaw, ok := secret.Data["encryptions"]
	if ok {
		encryptions, ok := encryptionsRaw.(json.Number)
		if !ok {
			return nil, errors.New("could not convert encryptions to a number")
		}
		encryptions64, err := encryptions.Int64()
		if err != nil {
			return nil, err
		}
		result.Encryptions = int(encryptions64)
	}

	return &result, err
}
