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

func (c *Sys) RotateStatus(recovery bool) (*RekeyStatusResponse, error) {
	return c.RotateStatusWithContext(context.Background(), recovery)
}

func (c *Sys) RotateStatusWithContext(ctx context.Context, recovery bool) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/init"
	} else {
		requestPath = "/v1/sys/rotate/root/init"
	}
	r := c.c.NewRequest(http.MethodGet, requestPath)

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

func (c *Sys) RotateInit(config *RekeyInitRequest, recovery bool) (*RekeyStatusResponse, error) {
	return c.RotateInitWithContext(context.Background(), config, recovery)
}

func (c *Sys) RotateInitWithContext(ctx context.Context, config *RekeyInitRequest, recovery bool) (*RekeyStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/init"
	} else {
		requestPath = "/v1/sys/rotate/root/init"
	}
	r := c.c.NewRequest(http.MethodPost, requestPath)
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

func (c *Sys) RotateCancel(recovery bool) error {
	return c.RotateCancelWithContext(context.Background(), recovery)
}

func (c *Sys) RotateCancelWithContext(ctx context.Context, recovery bool) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/init"
	} else {
		requestPath = "/v1/sys/rotate/root/init"
	}
	r := c.c.NewRequest(http.MethodDelete, requestPath)

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateUpdate(shard, nonce string, recovery bool) (*RekeyUpdateResponse, error) {
	return c.RotateUpdateWithContext(context.Background(), shard, nonce, recovery)
}

func (c *Sys) RotateUpdateWithContext(ctx context.Context, shard, nonce string, recovery bool) (*RekeyUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/update"
	} else {
		requestPath = "/v1/sys/rotate/root/update"
	}
	r := c.c.NewRequest(http.MethodPut, requestPath)
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

func (c *Sys) RotateRetrieveBackup(recovery bool) (*RekeyRetrieveResponse, error) {
	return c.RotateRetrieveBackupWithContext(context.Background(), recovery)
}

func (c *Sys) RotateRetrieveBackupWithContext(ctx context.Context, recovery bool) (*RekeyRetrieveResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/backup"
	} else {
		requestPath = "/v1/sys/rotate/root/backup"
	}
	r := c.c.NewRequest(http.MethodGet, requestPath)
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

func (c *Sys) RotateDeleteBackup(recovery bool) error {
	return c.RekeyDeleteBackupWithContext(context.Background())
}

func (c *Sys) RotateDeleteBackupWithContext(ctx context.Context, recovery bool) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/backup"
	} else {
		requestPath = "/v1/sys/rotate/root/backup"
	}
	r := c.c.NewRequest(http.MethodDelete, requestPath)

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Sys) RotateVerificationStatus(recovery bool) (*RekeyVerificationStatusResponse, error) {
	return c.RotateVerificationStatusWithContext(context.Background(), recovery)
}

func (c *Sys) RotateVerificationStatusWithContext(ctx context.Context, recovery bool) (*RekeyVerificationStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/verify"
	} else {
		requestPath = "/v1/sys/rotate/root/verify"
	}
	r := c.c.NewRequest(http.MethodGet, requestPath)
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

func (c *Sys) RotateVerificationUpdate(shard, nonce string, recovery bool) (*RekeyVerificationUpdateResponse, error) {
	return c.RotateVerificationUpdateWithContext(context.Background(), shard, nonce, recovery)
}

func (c *Sys) RotateVerificationUpdateWithContext(ctx context.Context, shard, nonce string, recovery bool) (*RekeyVerificationUpdateResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/verify"
	} else {
		requestPath = "/v1/sys/rotate/root/verify"
	}
	r := c.c.NewRequest(http.MethodPut, requestPath)
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

func (c *Sys) RotateVerificationCancel(recovery bool) error {
	return c.RotateVerificationCancelWithContext(context.Background(), recovery)
}

func (c *Sys) RotateVerificationCancelWithContext(ctx context.Context, recovery bool) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	var requestPath string
	if recovery {
		requestPath = "/v1/sys/rotate/recovery/verify"
	} else {
		requestPath = "/v1/sys/rotate/root/verify"
	}
	r := c.c.NewRequest(http.MethodDelete, requestPath)

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

// Depreacted: use RotateKeyringWithContext instead.
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
	return c.RotateWithContext(context.Background())
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
