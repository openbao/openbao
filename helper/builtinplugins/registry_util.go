//go:build !enterprise

package builtinplugins

import "github.com/openbao/openbao/sdk/helper/consts"

// IsBuiltinEntPlugin checks whether the plugin is an enterprise only builtin plugin
func (r *registry) IsBuiltinEntPlugin(name string, pluginType consts.PluginType) bool {
	return false
}
