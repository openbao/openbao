// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// DeleteNamespaceOutput is returned by DeleteNamespace.
type DeleteNamespaceOutput struct {
	Status string `json:"status"`
}

// DeleteNamespace removes the namespace with the given name. If the namespace
// is sealed and the caller holds sudo privilege on the path, the server
// automatically performs a physical storage wipe.
func (c *Sys) DeleteNamespace(name string) (*DeleteNamespaceOutput, error) {
	return c.DeleteNamespaceWithContext(context.Background(), name)
}

// DeleteNamespaceWithContext removes the namespace with the given name. If the
// namespace is sealed and the caller holds sudo privilege on the path, the
// server automatically performs a physical storage wipe.
func (c *Sys) DeleteNamespaceWithContext(ctx context.Context, name string) (*DeleteNamespaceOutput, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *DeleteNamespaceOutput
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}
