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

func (c *Sys) RotateRootStatus() (*RekeyStatusResponse, error) {
	return c.RotateRootStatusWithContext(context.Background())
}

func (c *Sys) RotateRootStatusWithContext(ctx context.Context) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/root/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RekeyStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryStatus() (*RekeyStatusResponse, error) {
	return c.RotateRecoveryStatusWithContext(context.Background())
}

func (c *Sys) RotateRecoveryStatusWithContext(ctx context.Context) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/recovery/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RekeyStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootInit(config *RekeyInitRequest) (*RekeyStatusResponse, error) {
	return c.RotateRootInitWithContext(context.Background(), config)
}

func (c *Sys) RotateRootInitWithContext(ctx context.Context, config *RekeyInitRequest) (*RekeyStatusResponse, error) {
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
		Data *RekeyStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryInit(config *RekeyInitRequest) (*RekeyStatusResponse, error) {
	return c.RotateRecoveryInitWithContext(context.Background(), config)
}

func (c *Sys) RotateRecoveryInitWithContext(ctx context.Context, config *RekeyInitRequest) (*RekeyStatusResponse, error) {
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
		Data *RekeyStatusResponse
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

func (c *Sys) RotateRootUpdate(shard, nonce string) (*RekeyUpdateResponse, error) {
	return c.RotateRootUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRootUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyUpdateResponse, error) {
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
		Data *RekeyUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryUpdate(shard, nonce string) (*RekeyUpdateResponse, error) {
	return c.RotateRecoveryUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRecoveryUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyUpdateResponse, error) {
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
		Data *RekeyUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootRetrieveBackup() (*RekeyRetrieveResponse, error) {
	return c.RotateRootRetrieveBackupWithContext(context.Background())
}

func (c *Sys) RotateRootRetrieveBackupWithContext(ctx context.Context) (*RekeyRetrieveResponse, error) {
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

	var result RekeyRetrieveResponse
	err = mapstructure.Decode(secret.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (c *Sys) RotateRecoveryRetrieveBackup() (*RekeyRetrieveResponse, error) {
	return c.RotateRecoveryRetrieveBackupWithContext(context.Background())
}

func (c *Sys) RotateRecoveryRetrieveBackupWithContext(ctx context.Context) (*RekeyRetrieveResponse, error) {
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

	var result RekeyRetrieveResponse
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

func (c *Sys) RotateRootVerificationStatus() (*RekeyVerificationStatusResponse, error) {
	return c.RotateRootVerificationStatusWithContext(context.Background())
}

func (c *Sys) RotateRootVerificationStatusWithContext(ctx context.Context) (*RekeyVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/root/verify")
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RekeyVerificationStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryVerificationStatus() (*RekeyVerificationStatusResponse, error) {
	return c.RotateRecoveryVerificationStatusWithContext(context.Background())
}

func (c *Sys) RotateRecoveryVerificationStatusWithContext(ctx context.Context) (*RekeyVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/rotate/recovery/verify")
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data *RekeyVerificationStatusResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRootVerificationUpdate(shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
	return c.RotateRootVerificationUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRootVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
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
		Data *RekeyVerificationUpdateResponse
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) RotateRecoveryVerificationUpdate(shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
	return c.RotateRecoveryVerificationUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) RotateRecoveryVerificationUpdateWithContext(ctx context.Context, shard, nonce string) (*RekeyVerificationUpdateResponse, error) {
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
		Data *RekeyVerificationUpdateResponse
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

type KeyStatus struct {
	Term        int       `json:"term"`
	InstallTime time.Time `json:"install_time"`
	Encryptions int       `json:"encryptions"`
}
