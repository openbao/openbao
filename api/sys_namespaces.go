// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ForceDeleteNamespaceOutput is returned by ForceDeleteNamespace.
type ForceDeleteNamespaceOutput struct {
	Status string `json:"status"`
}

// ForceDeleteNamespace removes a sealed namespace by erasing its physical
// storage. The caller must hold sudo privilege on the path.
func (c *Sys) ForceDeleteNamespace(name string) (*ForceDeleteNamespaceOutput, error) {
	return c.ForceDeleteNamespaceWithContext(context.Background(), name)
}

// ForceDeleteNamespaceWithContext removes a sealed namespace by erasing its
// physical storage. The caller must hold sudo privilege on the path.
func (c *Sys) ForceDeleteNamespaceWithContext(ctx context.Context, name string) (*ForceDeleteNamespaceOutput, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", name))
	r.Params.Set("force", "true")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *ForceDeleteNamespaceOutput
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}
