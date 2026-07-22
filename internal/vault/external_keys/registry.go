// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ek

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/kmsplugin"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

const (
	// StoragePrefix is the storage prefix used by external keys, under the sys/
	// prefix.
	StoragePrefix = "external-keys/"

	// KeyStoragePrefix is the storage prefix for keys.
	KeyStoragePrefix = StoragePrefix + "keys/"

	// ConfigStoragePrefix is the storage prefix for configs.
	ConfigStoragePrefix = StoragePrefix + "configs/"
)

// ConfigEntry represents a config mapping in storage.
type ConfigEntry struct {
	Plugin string         `json:"plugin"` // Name of the plugin to use with this config, e.g., "transit".
	Values map[string]any `json:"values"` // Config map values to pass to OpenKMS().
}

// KeyEntry represents a key mapping in storage.
type KeyEntry struct {
	Values map[string]any      `json:"values"` // Config map values to pass to GetKey().
	Grants map[string]struct{} `json:"grants"` // Set of mount paths that may access this key.
}

type lockKey struct {
	config      string
	namespaceID string
}

// Registry manages storage entries and handles requests for instantiation of
// keys, caching KMS instances between requests.
type Registry struct {
	logger  log.Logger
	plugins *kmsplugin.Catalog

	// Namespace ID -> Config name -> Client.
	cache     map[string]map[string]kms.KMS
	cacheLock sync.Mutex // Guards cache.

	// These locks guard storage and inflight cache entries, one lock per
	// namespace + config entry.
	locks *locksutil.KeyedCancelLock[lockKey]
}

// NewRegistry returns a new Registry.
func NewRegistry(plugins *kmsplugin.Catalog, logger log.Logger) *Registry {
	return &Registry{
		logger:  logger,
		plugins: plugins,
		cache:   make(map[string]map[string]kms.KMS),
		locks:   locksutil.NewKeyedCancelLock[lockKey](),
	}
}

func (r *Registry) cacheGet(ns *namespace.Namespace, name string) (kms.KMS, bool) {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()

	inner, ok := r.cache[ns.ID]
	if !ok {
		return nil, false
	}
	client, ok := inner[name]
	if !ok {
		return nil, false
	}

	return client, true
}

func (r *Registry) cachePut(ns *namespace.Namespace, name string, client kms.KMS) {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()

	inner, ok := r.cache[ns.ID]
	if !ok {
		// Ensure a namespace-level map is present.
		inner = make(map[string]kms.KMS, 1)
		r.cache[ns.ID] = inner
	}

	inner[name] = client
}

func (r *Registry) cachePop(ns *namespace.Namespace, name string) (kms.KMS, bool) {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()

	inner, ok := r.cache[ns.ID]
	if !ok {
		return nil, false
	}
	client, ok := inner[name]
	if !ok {
		return nil, false
	}

	delete(inner, name)
	if len(inner) == 0 {
		// Remove the namespace-level map if it is now empty.
		delete(r.cache, ns.ID)
	}

	return client, true
}

func (r *Registry) openKMS(ctx context.Context, ce *ConfigEntry) (kms.KMS, error) {
	return r.plugins.OpenKMS(ctx, ce.Plugin, &kms.OpenOptions{
		Logger:    r.logger.Named(ce.Plugin),
		ConfigMap: ce.Values,
	})
}

// ListConfigs lists all configs present in the passed system storage.
func (r *Registry) ListConfigs(ctx context.Context, s logical.Storage, after string, limit int) ([]string, error) {
	return s.ListPage(ctx, ConfigStoragePrefix, after, limit)
}

// ReadConfig reads a config entry from the passed storage.
func (r *Registry) ReadConfig(ctx context.Context, s logical.Storage, name string) (*ConfigEntry, error) {
	entry, err := s.Get(ctx, path.Join(ConfigStoragePrefix, name))
	switch {
	case err != nil:
		return nil, fmt.Errorf("failed to read config: %w", err)
	case entry == nil:
		return nil, nil
	}

	var ce ConfigEntry
	if err := entry.DecodeJSON(&ce); err != nil {
		return nil, fmt.Errorf("failed to decode storage entry: %w", err)
	}

	return &ce, nil
}

// ModifyConfig reads and writes back a config entry, optionally instantiating
// it against the respective plugin to ensure it is working.
func (r *Registry) ModifyConfig(ctx context.Context, s logical.Storage, name string, verify bool, f func(ce *ConfigEntry, exists bool) error) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	lockKey := lockKey{
		config:      name,
		namespaceID: ns.ID,
	}

	if err := r.locks.Lock(ctx, lockKey); err != nil {
		return err
	}

	defer r.locks.Unlock(lockKey)

	// Read the current config entry.
	ce, err := r.ReadConfig(ctx, s, name)
	if err != nil {
		return err
	}

	exists := ce != nil
	if !exists {
		ce = &ConfigEntry{}
	}

	// Update the config via the provided callback.
	if err := f(ce, exists); err != nil {
		return err
	}

	client, ok := r.cachePop(ns, name)
	if ok {
		// Close an existing client before re-opening it against the new config.
		// This should help with plugins that do not easily support differing
		// configurations to be active at once, e.g., PKCS#11.
		if err := client.Close(ctx); err != nil {
			// There's no reason to fail the request if an old client fails to
			// close, so just log it.
			r.logger.Error("failed to close client", "error", err.Error(), "config", name, "namespace", ns.Path)
		}
	}

	// In verify mode, storage should only be updated if the config yields
	// a working client. If the storage write fails however, a successfully
	// created client must close again.
	var wrote bool

	if verify {
		client, err := r.openKMS(ctx, ce)
		if err != nil {
			return err
		}

		defer func() {
			if wrote {
				// A client is created mainly for verification, but it can be
				// made available in the cache for later use, too.
				r.cachePut(ns, name, client)
				return
			}

			// If the storage write failed, close the client again.
			if err := client.Close(ctx); err != nil {
				r.logger.Error("failed to close client", "error", err.Error(), "config", name, "namespace", ns.Path)
			}
		}()
	}

	// Persist the config entry.
	entry, err := logical.StorageEntryJSON(path.Join(ConfigStoragePrefix, name), ce)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to store config: %w", err)
	}

	wrote = true

	return nil
}

// DeleteConfig deletes a config entry and all of its key entries from the
// passed storage.
func (r *Registry) DeleteConfig(ctx context.Context, s logical.Storage, name string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	lockKey := lockKey{
		config:      name,
		namespaceID: ns.ID,
	}

	if err := r.locks.Lock(ctx, lockKey); err != nil {
		return err
	}

	defer r.locks.Unlock(lockKey)

	client, ok := r.cachePop(ns, name)
	if ok {
		if err := client.Close(ctx); err != nil {
			// There's no reason to fail the request if an old client fails to
			// close, so just log it.
			r.logger.Error("failed to close client", "error", err.Error(), "config", name, "namespace", ns.Path)
		}
	}

	// Delete key entries first.
	if err := logical.ClearViewWithPagination(
		ctx,
		logical.NewStorageView(s, path.Join(KeyStoragePrefix, name)+"/"),
		r.logger,
	); err != nil {
		return fmt.Errorf("failed to clear keys: %w", err)
	}

	// Then delete the config entry.
	if err := s.Delete(ctx, path.Join(ConfigStoragePrefix, name)); err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}

	return nil
}

// InvalidateConfig is called by core's invalidation manager to clear a cached
// client when a config was modified.
func (r *Registry) InvalidateConfig(ctx context.Context, name string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	client, ok := r.cachePop(ns, name)
	if !ok {
		// Nothing to do.
		return nil
	}

	if err := client.Close(ctx); err != nil {
		r.logger.Error("failed to close client", "error", err, "config", name, "namespace", ns.Path)
	}

	return nil
}

// ListKeys lists all keys for the given config present in the passed system
// storage.
func (r *Registry) ListKeys(ctx context.Context, s logical.Storage, config string, after string, limit int) ([]string, error) {
	return s.ListPage(ctx, path.Join(KeyStoragePrefix, config)+"/", after, limit)
}

// ReadKey reads a key entry from the passed storage.
func (r *Registry) ReadKey(ctx context.Context, s logical.Storage, configName, keyName string) (*KeyEntry, error) {
	entry, err := s.Get(ctx, path.Join(KeyStoragePrefix, configName, keyName))
	switch {
	case err != nil:
		return nil, fmt.Errorf("failed to read key: %w", err)
	case entry == nil:
		return nil, nil
	}

	var ke KeyEntry
	if err := entry.DecodeJSON(&ke); err != nil {
		return nil, fmt.Errorf("failed to decode storage entry: %w", err)
	}

	return &ke, nil
}

// ModifyKey reads and writes back a key entry, optionally instantiating it
// against the respective plugin to ensure it is working.
func (r *Registry) ModifyKey(ctx context.Context, s logical.Storage, configName, keyName string, verify bool, f func(ke *KeyEntry, exists bool) error) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	lockKey := lockKey{
		config:      configName,
		namespaceID: ns.ID,
	}

	if err := r.locks.Lock(ctx, lockKey); err != nil {
		return err
	}

	defer r.locks.Unlock(lockKey)

	// Read the corresponding config entry first.
	ce, err := r.ReadConfig(ctx, s, configName)
	switch {
	case err != nil:
		return err
	case ce == nil:
		return fmt.Errorf("config %q does not exist", configName)
	}

	// Then also read the existing key entry, if any.
	ke, err := r.ReadKey(ctx, s, configName, keyName)
	if err != nil {
		return err
	}

	exists := ke != nil
	if !exists {
		ke = &KeyEntry{}
	}

	// Update the key via the provided callback.
	if err := f(ke, exists); err != nil {
		return err
	}

	if verify {
		// To verify a key, first ensure a client is present in cache. Unlike
		// ModifyConfig, this method does not persist new config data, so it can
		// insert to cache right away.
		client, ok := r.cacheGet(ns, configName)
		if !ok {
			client, err = r.openKMS(ctx, ce)
			if err != nil {
				return err
			}
			r.cachePut(ns, configName, client)
		}

		// Then use it to get the key.
		key, err := client.GetKey(ctx, &kms.KeyOptions{ConfigMap: ke.Values})
		if err != nil {
			return err
		}

		// Unlike KMS clients, keys aren't cached so just close it again.
		if err := key.Close(ctx); err != nil {
			r.logger.Error("failed to close key", "error", err.Error(), "config", configName, "key", keyName, "namespace", ns.Path)
		}
	}

	// Persist the key entry.
	entry, err := logical.StorageEntryJSON(path.Join(KeyStoragePrefix, configName, keyName), ke)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	return nil
}

// DeleteKey deletes a key entry from the passed storage.
func (r *Registry) DeleteKey(ctx context.Context, s logical.Storage, configName, keyName string) error {
	if err := s.Delete(ctx, path.Join(KeyStoragePrefix, configName, keyName)); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	return nil
}

// GetExternalKey is called by core's system view implementation to instantiate
// a key and hand it to a plugin.
func (r *Registry) GetExternalKey(ctx context.Context, s logical.Storage, ns *namespace.Namespace, mount, ref string) (kms.Key, error) {
	configName, keyName, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}

	ke, err := r.ReadKey(ctx, s, configName, keyName)
	switch {
	case err != nil:
		return nil, err
	case ke == nil:
		return nil, fmt.Errorf("key %q does not exist", ref)
	}

	// Check that the requesting mount has access to this key.
	if _, ok := ke.Grants[mount]; !ok {
		r.logger.Trace("key access rejected", "namespace", ns.Path, "mount", mount, "ref", ref)
		return nil, fmt.Errorf("mount %q is missing grant for key %q", mount, ref)
	}

	r.logger.Trace("key access granted", "namespace", ns.Path, "mount", mount, "ref", ref)

	client, err := r.GetClient(ctx, s, ns, configName)
	if err != nil {
		return nil, err
	}

	return client.GetKey(ctx, &kms.KeyOptions{ConfigMap: ke.Values})
}

var (
	// When a config or key is set via the system backend, framework already
	// ensures that their names are sane. However, the same check must run
	// against names passed in by a plugin via the system view.
	namePattern   = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")
	errInvalidRef = errors.New(`invalid key reference: must be "<config name>:<key name>"`)
)

// ParseRef parses a key reference into config name and key name.
func ParseRef(input string) (string, string, error) {
	parts := strings.SplitN(input, ":", 2)

	if len(parts) != 2 {
		return "", "", errInvalidRef
	}

	for _, part := range parts {
		if !namePattern.MatchString(part) {
			return "", "", errInvalidRef
		}
	}

	return parts[0], parts[1], nil
}

// GetClient returns a cached client or creates a missing one and caches it.
func (r *Registry) GetClient(ctx context.Context, s logical.Storage, ns *namespace.Namespace, name string) (kms.KMS, error) {
	// Fast path:
	client, ok := r.cacheGet(ns, name)
	if ok {
		return client, nil
	}

	lockKey := lockKey{
		config:      name,
		namespaceID: ns.ID,
	}

	if err := r.locks.Lock(ctx, lockKey); err != nil {
		return nil, err
	}

	defer r.locks.Unlock(lockKey)

	// Refresh cache:
	client, ok = r.cacheGet(ns, name)
	if ok {
		return client, nil
	}

	ce, err := r.ReadConfig(ctx, s, name)
	switch {
	case err != nil:
		return nil, err
	case ce == nil:
		return nil, fmt.Errorf("config %q does not exist", name)
	}

	client, err = r.openKMS(ctx, ce)
	if err != nil {
		return nil, err
	}

	r.cachePut(ns, name, client)
	return client, nil
}

// CleanupNamespace is called when a namespace is deleted or sealed.
func (r *Registry) CleanupNamespace(ctx context.Context, ns *namespace.Namespace) {
	// Pop the entire namespace-level map off the cache.
	r.cacheLock.Lock()
	inner, ok := r.cache[ns.ID]
	delete(r.cache, ns.ID)
	r.cacheLock.Unlock()

	if !ok {
		return
	}

	var wg sync.WaitGroup
	for name, client := range inner {
		wg.Go(func() {
			if err := client.Close(ctx); err != nil {
				r.logger.Error("failed to close client", "error", err.Error(), "config", name, "namespace", ns.Path)
			}
		})
	}

	wg.Wait()
}

// Stop is called when core seals.
func (r *Registry) Stop(ctx context.Context) {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()

	var wg sync.WaitGroup
	for nsID, inner := range r.cache {
		for name, client := range inner {
			wg.Go(func() {
				if err := client.Close(ctx); err != nil {
					r.logger.Error("failed to close client", "error", err.Error(), "config", name, "namespace_id", nsID)
				}
			})
		}
	}

	wg.Wait()
}
