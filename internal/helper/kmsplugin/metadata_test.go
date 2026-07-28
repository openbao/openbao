// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/stretchr/testify/require"
)

func TestMetadata(t *testing.T) {
	ctx := t.Context()
	logger := hclog.Default()

	tests := map[string]*server.Config{
		"builtin": {},
		"external": {
			PluginDirectory: filepath.Dir(os.Args[0]),
			Plugins:         []*server.PluginConfig{TransitPluginConfig},
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			catalog, err := NewCatalog(logger, config)
			require.NoError(t, err)

			meta, err := catalog.GetMetadata(ctx, "transit")
			require.NoError(t, err)
			require.Equal(t, builtinMetadata["transit"], meta)
		})
	}
}
