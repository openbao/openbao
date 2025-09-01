// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// reloadMatchingPluginMounts reloads provided mounts, regardless of
// plugin name, as long as the backend type is plugin.
func (c *Core) reloadMatchingPluginMounts(ctx context.Context, mounts []string) error {
	c.mountsLock.RLock()
	defer c.mountsLock.RUnlock()
	c.authLock.RLock()
	defer c.authLock.RUnlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	var errors error
	for _, mount := range mounts {
		var isAuth bool
		// allow any of
		//   - sys/auth/foo/
		//   - sys/auth/foo
		//   - auth/foo/
		//   - auth/foo
		if strings.HasPrefix(mount, credentialRoutePrefix) {
			isAuth = true
		} else if strings.HasPrefix(mount, mountPathSystem+credentialRoutePrefix) {
			isAuth = true
			mount = strings.TrimPrefix(mount, mountPathSystem)
		}
		if !strings.HasSuffix(mount, "/") {
			mount += "/"
		}

		entry := c.router.MatchingMountEntry(ctx, mount)
		if entry == nil {
			errors = multierror.Append(errors, fmt.Errorf("cannot fetch mount entry on %q", mount))
			continue
		}

		// We dont reload mounts that are not in the same namespace
		if ns.ID != entry.Namespace().ID {
			continue
		}

		err := c.reloadBackendCommon(ctx, entry, isAuth)
		if err != nil {
			errors = multierror.Append(errors, fmt.Errorf("cannot reload plugin on %q: %w", mount, err))
			continue
		}
		c.logger.Info("successfully reloaded plugin", "plugin", entry.Accessor, "path", entry.Path, "version", entry.Version)
	}
	return errors
}

// reloadPlugin reloads all mounted backends that are of
// plugin pluginName (name of the plugin as registered in
// the plugin catalog).
func (c *Core) reloadMatchingPlugin(ctx context.Context, pluginName string) error {
	c.mountsLock.RLock()
	defer c.mountsLock.RUnlock()
	c.authLock.RLock()
	defer c.authLock.RUnlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Filter mount entries that only matches the plugin name
	for _, entry := range c.mounts.Entries {
		// We dont reload mounts that are not in the same namespace
		if ns.ID != entry.Namespace().ID {
			continue
		}
		if entry.Type == pluginName || (entry.Type == "plugin" && entry.Config.PluginName == pluginName) {
			err := c.reloadBackendCommon(ctx, entry, false)
			if err != nil {
				return err
			}
			c.logger.Info("successfully reloaded plugin", "plugin", pluginName, "path", entry.Path, "version", entry.Version)
		}
	}

	// Filter auth mount entries that ony matches the plugin name
	for _, entry := range c.auth.Entries {
		// We dont reload mounts that are not in the same namespace
		if ns.ID != entry.Namespace().ID {
			continue
		}

		if entry.Type == pluginName || (entry.Type == "plugin" && entry.Config.PluginName == pluginName) {
			err := c.reloadBackendCommon(ctx, entry, true)
			if err != nil {
				return err
			}
			c.logger.Info("successfully reloaded plugin", "plugin", entry.Accessor, "path", entry.Path, "version", entry.Version)
		}
	}

	return nil
}

// reloadBackendCommon is a generic method to reload a backend provided a
// MountEntry.
func (c *Core) reloadBackendCommon(ctx context.Context, entry *MountEntry, isAuth bool) error {
	// Make sure our cache is up-to-date. Since some singleton mounts can be
	// tuned, we do this before the below check.
	entry.SyncCache()

	// We don't want to reload the singleton mounts. They often have specific
	// inmemory elements and we don't want to touch them here.
	if slices.Contains(singletonMounts, entry.Type) {
		c.logger.Debug("skipping reload of singleton mount", "type", entry.Type)
		return nil
	}

	path := entry.Path

	if isAuth {
		path = credentialRoutePrefix + path
	}

	// Fast-path out if the backend doesn't exist
	raw, ok := c.router.root.Get(entry.Namespace().Path + path)
	if !ok {
		return nil
	}

	re := raw.(*routeEntry)

	// Grab the lock, this allows requests to drain before we cleanup the
	// client.
	re.l.Lock()
	defer re.l.Unlock()

	// Only call Cleanup if backend is initialized
	if re.backend != nil {
		// Pass a context value so that the plugin client will call the
		// appropriate cleanup method for reloading
		reloadCtx := context.WithValue(ctx, plugin.ContextKeyPluginReload, "reload")
		// Call backend's Cleanup routine
		re.backend.Cleanup(reloadCtx)
	}

	view := re.storageView
	sysView := c.mountEntrySysView(entry)

	var backend logical.Backend
	var err error
	oldSha := entry.RunningSha256
	if !isAuth {
		// Dispense a new backend
		backend, entry.RunningSha256, err = c.newLogicalBackend(ctx, entry, sysView, view)
	} else {
		backend, entry.RunningSha256, err = c.newCredentialBackend(ctx, entry, sysView, view)
	}
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend of type %q returned from creation function", entry.Type)
	}

	// update the entry running version with the configured version, which was verified during registration.
	entry.RunningVersion = entry.Version
	if entry.RunningVersion == "" {
		// don't set the running version to a builtin if it is running as an external plugin
		if entry.RunningSha256 == "" {
			if isAuth {
				entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeCredential, entry.Type)
			} else {
				entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeSecrets, entry.Type)
			}
		}
	}

	// update the mount table since we changed the runningSha
	if oldSha != entry.RunningSha256 && MountTableUpdateStorage {
		if isAuth {
			err = c.persistAuth(ctx, nil, c.auth, &entry.Local, entry.UUID)
			if err != nil {
				return err
			}
		} else {
			err = c.persistMounts(ctx, nil, c.mounts, &entry.Local, entry.UUID)
			if err != nil {
				return err
			}
		}
	}

	// Set the backend back
	re.backend = backend

	// Initialize the backend after reload. This is a no-op for backends < v5 which
	// rely on lazy loading for initialization. v5 backends do not rely on lazy loading
	// for initialization unless the plugin process is killed. Reload of a v5 backend
	// results in a new plugin process, so we must initialize the backend here.
	err = backend.Initialize(ctx, &logical.InitializationRequest{Storage: view})
	if err != nil {
		return err
	}

	// Set paths as well
	paths := backend.SpecialPaths()
	if paths != nil {
		re.rootPaths.Store(pathsToRadix(paths.Root))
		loginPathsEntry, err := parseUnauthenticatedPaths(paths.Unauthenticated)
		if err != nil {
			return err
		}
		re.loginPaths.Store(loginPathsEntry)
	}

	return nil
}
