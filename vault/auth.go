// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreAuthConfigPath is used to store the auth configuration.
	// Auth configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuthConfigPath = "core/auth"

	// coreLocalAuthConfigPath is used to store credential configuration for
	// local (non-replicated) mounts
	coreLocalAuthConfigPath = "core/local-auth"

	// credentialBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the credential backends.
	credentialBarrierPrefix = "auth/"

	// credentialRoutePrefix is the mount prefix used for the router
	credentialRoutePrefix = "auth/"

	// credentialTableType is the value we expect to find for the credential
	// table and corresponding entries
	credentialTableType = "auth"
)

var (
	// credentialAliases maps old backend names to new backend names, allowing us
	// to move/rename backends but maintain backwards compatibility
	credentialAliases = map[string]string{"aws-ec2": "aws"}

	// protectedAuths marks auth mounts that are protected and cannot be remounted
	protectedAuths = []string{
		"auth/token",
	}
)

func newAuthMountsTable(core *Core) *mountable {
	return &mountable{
		core:      core,
		tableType: credentialTableType,
		path:      coreAuthConfigPath,
		localPath: coreLocalAuthConfigPath,
	}
}

func (c *Core) setupAuthMounts(ctx context.Context) error {
	c.authMounts = newAuthMountsTable(c)

	if err := c.authMounts.loadMounts(ctx); err != nil {
		return err
	}

	return c.authMounts.setupMounts(ctx)
}

// newCredentialBackend is used to create and configure a new credential backend by name.
// It also returns the SHA256 of the plugin, if available.
func (c *Core) newCredentialBackend(ctx context.Context, entry *MountEntry, sysView logical.SystemView, view logical.Storage) (logical.Backend, string, error) {
	t := entry.Type
	if alias, ok := credentialAliases[t]; ok {
		t = alias
	}

	var runningSha string
	f, ok := c.credentialBackends[t]
	if !ok {
		plug, err := c.pluginCatalog.Get(ctx, t, consts.PluginTypeCredential, entry.Version)
		if err != nil {
			return nil, "", err
		}
		if plug == nil {
			errContext := t
			if entry.Version != "" {
				errContext += fmt.Sprintf(", version=%s", entry.Version)
			}
			return nil, "", fmt.Errorf("%w: %s", ErrPluginNotFound, errContext)
		}
		if len(plug.Sha256) > 0 {
			runningSha = hex.EncodeToString(plug.Sha256)
		}

		f = plugin.Factory
		if !plug.Builtin {
			f = wrapFactoryCheckPerms(c, plugin.Factory)
		}
	}
	// Set up conf to pass in plugin_name
	conf := make(map[string]string)
	for k, v := range entry.Options {
		conf[k] = v
	}

	switch entry.Type {
	case "plugin":
		conf["plugin_name"] = entry.Config.PluginName
	default:
		conf["plugin_name"] = t
	}

	conf["plugin_type"] = consts.PluginTypeCredential.String()
	conf["plugin_version"] = entry.Version

	authLogger := c.baseLogger.Named(fmt.Sprintf("auth.%s.%s", t, entry.Accessor))
	c.AddLogger(authLogger)

	config := &logical.BackendConfig{
		StorageView: view,
		Logger:      authLogger,
		Config:      conf,
		System:      sysView,
		BackendUUID: entry.BackendAwareUUID,
	}

	b, err := f(ctx, config)
	if err != nil {
		return nil, "", err
	}

	return b, runningSha, nil
}
