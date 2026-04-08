// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/osutil"
	"github.com/openbao/openbao/helper/pluginutil/oci"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

// Catalog manages dispatches to builtin and external KMS plugins and manages
// their processes & connections. This is disjoint from the "main" plugin
// catalog in core as KMS plugins may need to be instantiated before core is
// created. Additionally, we get to simplify many things as KMS plugins are
// declarative only.
type Catalog struct {
	logger hclog.Logger

	mu         sync.Mutex
	plugins    map[string]*server.PluginConfig
	clients    map[string]*Client
	pluginType consts.PluginType
	handshake  plugin.HandshakeConfig
	pluginsets map[int]plugin.PluginSet

	// Derived from server configuration.
	pluginDirectory       string
	pluginFileUid         int
	pluginFilePermissions int
}

// NewCatalog returns a new KMS plugin catalog.
func NewCatalog(
	logger hclog.Logger,
	config *server.Config,
	pluginType consts.PluginType,
	handshake plugin.HandshakeConfig,
	pluginsets map[int]plugin.PluginSet,
) (*Catalog, error) {
	pluginDirectory := config.PluginDirectory
	if pluginDirectory != "" {
		var err error
		pluginDirectory, err = filepath.Abs(pluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("expand plugin directory: %w", err)
		}
		pluginDirectory, err = filepath.EvalSymlinks(pluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("expand plugin directory: %w", err)
		}
	}

	// Index plugin configs by name for easy lookup and to ensure there are no
	// naming conflicts.
	plugins := make(map[string]*server.PluginConfig)
	for _, plugin := range config.Plugins {
		// Ignore plugins that don't concern this catalog.
		if typ, _ := consts.ParsePluginType(plugin.Type); typ != pluginType {
			continue
		}
		// For now, KMS plugins only support one version at a time.
		if _, ok := plugins[plugin.Name]; ok {
			return nil, fmt.Errorf("cannot register several versions of plugin %q", plugin.Name)
		}
		plugins[plugin.Name] = plugin
	}

	return &Catalog{
		logger:                logger.Named(pluginType.String()),
		plugins:               plugins,
		clients:               make(map[string]*Client, len(plugins)),
		pluginType:            pluginType,
		handshake:             handshake,
		pluginsets:            pluginsets,
		pluginDirectory:       pluginDirectory,
		pluginFileUid:         config.PluginFileUid,
		pluginFilePermissions: config.PluginFilePermissions,
	}, nil
}

func (c *Catalog) GetClient(name string) (*Client, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.getClientLocked(name)
}

func (c *Catalog) CloseAll() {
}

func (c *Catalog) removeClientLocked(client *Client) {
	if stored, ok := c.clients[client.name]; ok && stored == client {
		delete(c.clients, client.name)
	}
}

func (c *Catalog) getClientLocked(name string) (*Client, bool, error) {
	// Try to reuse an existing client.
	if cl, ok := c.clients[name]; ok {
		cl.refs++
		return cl, true, nil
	}

	// Check for plugin configuration.
	config, ok := c.plugins[name]
	if !ok {
		return nil, false, nil
	}

	// Don't continue with external plugins if no plugin directory is set.
	if c.pluginDirectory == "" {
		return nil, true, errors.New("plugin directory not configured")
	}

	if err := c.checkFilePath(config); err != nil {
		return nil, true, err
	}

	checksum, err := hex.DecodeString(config.SHA256Sum)
	if err != nil {
		return nil, true, fmt.Errorf("invalid plugin sha256: %w", err)
	}

	// Spawn a new plugin process.
	exe := filepath.Join(c.pluginDirectory, config.CommandPath())
	cmd := exec.Command(exe, config.Args...)
	cmd.Env = append(cmd.Env, config.Env...)

	process := plugin.NewClient(&plugin.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: c.pluginsets,
		HandshakeConfig:  c.handshake,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           c.logger.Named(name),
		SecureConfig: &plugin.SecureConfig{
			Checksum: checksum,
			Hash:     sha256.New(),
		},
	})

	proto, err := process.Client()
	if err != nil {
		process.Kill()
		return nil, true, fmt.Errorf("start plugin client: %w", err)
	}

	cl := &Client{
		catalog:        c,
		name:           name,
		refs:           1,
		process:        process,
		ClientProtocol: proto,
	}
	c.clients[name] = cl
	return cl, true, nil
}

func (c *Catalog) reloadClient(prev *Client) (*Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	client, ok, err := c.getClientLocked(prev.name)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unknown plugin: %s", prev.name)
	}

	if client != prev {
		// This client was already reloaded, its address changed.
		return client, nil
	}

	// Call this for good measure - reloadClient should typically only be called
	// if the client is already known dead.
	prev.process.Kill()

	// Force a client recreation.
	delete(c.clients, prev.name)
	client, ok, err = c.getClientLocked(prev.name)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unknown plugin: %s", prev.name)
	}

	return client, nil
}

// checkFilePath mirrors path & permission checks performed by the core plugin
// catalog.
func (c *Catalog) checkFilePath(plugin *server.PluginConfig) error {
	// Best effort check to make sure the command isn't breaking out of the
	// configured plugin directory.
	path, err := filepath.EvalSymlinks(filepath.Join(c.pluginDirectory, plugin.CommandPath()))
	if err != nil {
		return fmt.Errorf("error while validating the command path: %w", err)
	}

	var ok bool
	if plugin.Image == "" {
		// Declarative, manual plugin.
		ok = filepath.Dir(path) == c.pluginDirectory
	} else {
		// Declarative, OCI-based plugin.
		ok = filepath.Dir(path) == filepath.Join(
			c.pluginDirectory, oci.PluginCacheDir, plugin.Slug(), plugin.SHA256Sum[:8])
	}
	if !ok {
		return errors.New("cannot execute files outside of configured plugin directory")
	}

	if env := api.ReadBaoVariable(consts.VaultEnableFilePermissionsCheckEnv); env != "" {
		enable, err := strconv.ParseBool(env)
		switch {
		case err != nil:
			return fmt.Errorf("failed to parse environment variable %s", consts.VaultEnableFilePermissionsCheckEnv)
		case enable:
			return osutil.OwnerPermissionsMatch(path, c.pluginFileUid, c.pluginFilePermissions)
		}
	}

	return nil
}

type Client struct {
	catalog *Catalog

	name string // Name of the plugin.
	refs int    // Reference count.

	process *plugin.Client
	plugin.ClientProtocol
}

// close decrements the client's reference count and kills it if the reference
// count reaches zero.
func (c *Client) Close() {
	c.catalog.mu.Lock()
	defer c.catalog.mu.Unlock()

	if c.refs == 0 {
		panic("pluginutil/catalog: tried to close client more than once")
	}

	c.refs--
	if c.refs != 0 {
		// Client remains live.
		return
	}

	// Last reference, so kill the process.
	c.process.Kill()

	// Remove from lookup if this is still the most recent client.
	c.catalog.removeClientLocked(c)
}

func (c *Client) Reload() (*Client, error) {
	return c.catalog.reloadClient(c)
}
