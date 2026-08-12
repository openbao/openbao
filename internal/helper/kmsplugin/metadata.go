// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"context"
	"fmt"

	"github.com/openbao/go-kms-wrapping/kms/transit/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
)

var builtinMetadata = map[string]plugin.Metadata{
	"transit": {
		SensitiveKMSFields: transit.SensitiveKMSFields,
	},
}

// GetMetadata returns a KMS plugin's metadata.
func (c *Catalog) GetMetadata(ctx context.Context, name string) (plugin.Metadata, error) {
	client, ok, err := c.getClient(name)
	switch {
	case err != nil:
		return plugin.Metadata{}, err

	case !ok:
		// Try builtin metadata.
		if meta, ok := builtinMetadata[name]; ok {
			return meta, nil
		} else {
			return plugin.Metadata{}, fmt.Errorf("unknown plugin: %s", name)
		}
	}

	raw, err := client.Dispense("metadata")
	if err != nil {
		client.close()
		return plugin.Metadata{}, err
	}

	return raw.(plugin.Metadata), nil
}
