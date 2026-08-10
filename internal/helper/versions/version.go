// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package versions

import (
	"fmt"
	"slices"
	"strings"

	semver "github.com/hashicorp/go-version"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/version"
)

const (
	BuiltinMetadata = "builtin"
)

var (
	DefaultBuiltinVersion = fmt.Sprintf("v%s+%s.bao", version.GetVersion().Version, BuiltinMetadata)
)

func GetBuiltinVersion(pluginType consts.PluginType, pluginName string) string {
	// pluginType and pluginName are ignored as of now.
	return DefaultBuiltinVersion
}

// IsBuiltinVersion checks for the "builtin" metadata identifier in a plugin's
// semantic version. Vault rejects any plugin registration requests with this
// identifier, so we can be certain it's a builtin plugin if it's present.
func IsBuiltinVersion(v string) bool {
	semanticVersion, err := semver.NewSemver(v)
	if err != nil {
		return false
	}

	metadataIdentifiers := strings.Split(semanticVersion.Metadata(), ".")
	return slices.Contains(metadataIdentifiers, BuiltinMetadata)
}
