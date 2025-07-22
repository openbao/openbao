// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

const (
	keyPath       = "%s/keys/%s"
	rotateKeyPath = "%s/keys/%s/rotate"

	wrappingKeyPath = "%s/wrapping_key"
	rewrapKeyPath   = "%s/rewrap/%s"

	encryptKeyPath = "%s/encrypt/%s"
	decryptKeyPath = "%s/decrypt/%s"
)

const (
	plaintextKey  = "plaintext"
	ciphertextKey = "ciphertext"
)

type Transit struct {
	c         *Client
	mountPath string
}

func (c *Client) Transit(mountPath string) *Transit {
	return &Transit{
		c:         c,
		mountPath: mountPath,
	}
}

func (t *Transit) CreateKeyWithContext(ctx context.Context, keyName string) error {
	r := t.c.NewRequest(http.MethodPut, fmt.Sprintf(keyPath, t.mountPath, keyName))
	_, err := t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) RotateKeyWithContext(ctx context.Context, keyName string) error {
	r := t.c.NewRequest(http.MethodPut, fmt.Sprintf(rotateKeyPath, t.mountPath, keyName))
	_, err := t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) GetWrappingKeyWithContext(ctx context.Context) (string, error) {
	r := t.c.NewRequest(http.MethodGet, fmt.Sprintf(wrappingKeyPath, t.mountPath))
	_, err := t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	return "", nil // TODO
}

func (t *Transit) RewrapKeyWithContext(ctx context.Context, keyName string, ciphertext string) (string, error) {
	r := t.c.NewRequest(http.MethodPut, fmt.Sprintf(rewrapKeyPath, t.mountPath, keyName))
	err := r.SetJSONBody(map[string]any{
		ciphertextKey: ciphertext,
	})
	if err != nil {
		return "", err
	}

	_, err = t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	return "", nil // TODO
}

func (t *Transit) ExportKeyWithContext(ctx context.Context, keyType string, keyName string) (string, error) {
	return "", errors.New("unimplemented")
}

func (t *Transit) EncryptWithContext(ctx context.Context, keyName string, plaintext string) (string, error) {
	r := t.c.NewRequest(http.MethodPut, fmt.Sprintf(encryptKeyPath, t.mountPath, keyName))
	err := r.SetJSONBody(map[string]any{
		plaintextKey: base64.RawStdEncoding.EncodeToString([]byte(plaintext)),
	})
	if err != nil {
		return "", err
	}

	_, err = t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	return "", nil // TODO
}

func (t *Transit) DecryptWithContext(ctx context.Context, keyName string, ciphertext string) (string, error) {
	r := t.c.NewRequest(http.MethodPut, fmt.Sprintf(decryptKeyPath, t.mountPath, keyName))
	err := r.SetJSONBody(map[string]any{
		ciphertextKey: ciphertext,
	})
	if err != nil {
		return "", err
	}

	_, err = t.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return "", err
	}
	return "", nil // TODO
}

func (t *Transit) CreateKey(keyName string) error {
	return t.CreateKeyWithContext(context.Background(), keyName)
}

func (t *Transit) RotateKey(keyName string) error {
	return t.RotateKeyWithContext(context.Background(), keyName)
}

func (t *Transit) GetWrappingKey(ctx context.Context) (string, error) {
	return t.GetWrappingKeyWithContext(context.Background())
}

func (t *Transit) RewrapKey(keyName string, ciphertext string) (string, error) {
	return t.RewrapKeyWithContext(context.Background(), keyName, ciphertext)
}

func (t *Transit) ExportKey(keyType string, keyName string) (string, error) {
	return t.ExportKeyWithContext(context.Background(), keyType, keyName)
}

func (t *Transit) Encrypt(keyName string, plaintext string) (string, error) {
	return t.EncryptWithContext(context.Background(), keyName, plaintext)
}

func (t *Transit) Decrypt(keyName string, ciphertext string) (string, error) {
	return t.DecryptWithContext(context.Background(), keyName, ciphertext)
}
