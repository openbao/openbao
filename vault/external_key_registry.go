// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// externalKeyRegistrySubPath is the storage sub path for
	// [ExternalKeyRegistry]. This is nested under the system view.
	externalKeyRegistrySubPath = "external-keys/"

	// externalKeyRegistryKeyPrefix is the storage prefix for key entries.
	externalKeyRegistryKeyPrefix = "keys/"

	// externalKeyRegistryConfigPrefix is the storage prefix for config entries.
	externalKeyRegistryConfigPrefix = "configs/"
)

// ExternalKeyRegistry provides durable storage of config and key mappings and
// uses these to expose KMS operations to mounts via [logical.ExternalKey].
type ExternalKeyRegistry struct {
	core   *Core
	logger hclog.Logger

	// storageLock is used in some edge cases where transactions are not enough
	// to ensure config <-> key consistency, essentially because we have no
	// concept of foreign key constraints.
	storageLock sync.RWMutex
}

// ExternalKey is the storage representation of a key.
type ExternalKey struct {
	// KMS-specific key parameters.
	Values map[string]string `json:"values"`

	// List of mount paths of plugins that may use this key.
	// Paths are relative to the key's namespace.
	Grants []string `json:"grants"`
}

// ExternalKeyConfig is the storage representation a config.
type ExternalKeyConfig struct {
	// Type of KMS. May be user-defined via the server config.
	Type string `json:"type"`

	// Name of a config in the parent namespace to inherit into this config's
	// namespace. Setting this field requires that Type and Values are empty.
	Inherits string `json:"inherits"`

	// KMS-specific client parameters.
	Values map[string]string `json:"values"`
}

// NewExternalKeyRegistry creates a new [ExternalKeyRegistry].
func NewExternalKeyRegistry(core *Core, logger hclog.Logger) *ExternalKeyRegistry {
	return &ExternalKeyRegistry{
		core:   core,
		logger: logger,
	}
}

// setupExternalKeys initializes [Core.externalKeys].
func (c *Core) setupExternalKeys() error {
	logger := c.baseLogger.Named("external-keys")
	c.AddLogger(logger)
	c.externalKeys = NewExternalKeyRegistry(c, logger)
	return nil
}

// teardownExternalKeys finalizes and zeroes [Core.externalKeys].
func (c *Core) teardownExternalKeys() error {
	if c.externalKeys == nil {
		return nil
	}
	c.externalKeys.Finalize()
	c.externalKeys = nil
	return nil
}

// storageViewForRequest returns the registry's root storage view based on the
// storage field of a [logical.Request], which should automatically be routed to
// the system barrier by the system backend.
func (r *ExternalKeyRegistry) storageViewForRequest(req *logical.Request) logical.Storage {
	return logical.NewStorageView(req.Storage, externalKeyRegistrySubPath)
}

// configPath returns the storage path for a config.
func (r *ExternalKeyRegistry) configPath(name string) string {
	return path.Join(externalKeyRegistryConfigPrefix, name)
}

// configListPath returns the storage path to list configs at.
func (r *ExternalKeyRegistry) configListPath() string {
	return externalKeyRegistryConfigPrefix
}

// keyPath returns the storage path for a key.
func (r *ExternalKeyRegistry) keyPath(name string) string {
	return path.Join(externalKeyRegistryKeyPrefix, name)
}

// keyListPath returns the storage path to list keys at.
func (r *ExternalKeyRegistry) keyListPath(name string) string {
	return path.Join(externalKeyRegistryKeyPrefix, name) + "/"
}

// getConfigCommon is a helper to read and deserialize a config from storage.
func (r *ExternalKeyRegistry) getConfigCommon(
	ctx context.Context, storage logical.Storage, name string,
) (*ExternalKeyConfig, error) {
	entry, err := storage.Get(ctx, r.configPath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	var config ExternalKeyConfig
	return &config, entry.DecodeJSON(&config)
}

// getKeyCommon is a helper to read and deserialize a key from storage.
func (r *ExternalKeyRegistry) getKeyCommon(
	ctx context.Context, storage logical.Storage, name string,
) (*ExternalKey, error) {
	entry, err := storage.Get(ctx, r.keyPath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	var key ExternalKey
	return &key, entry.DecodeJSON(&key)
}

// putConfigCommon is a helper to serialize and write a config to storage.
func (r *ExternalKeyRegistry) putConfigCommon(
	ctx context.Context, storage logical.Storage, name string, config *ExternalKeyConfig,
) error {
	entry, err := logical.StorageEntryJSON(r.configPath(name), config)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// putKeyCommon is a helper to serialize and write a key to storage.
func (r *ExternalKeyRegistry) putKeyCommon(
	ctx context.Context, storage logical.Storage, name string, key *ExternalKey,
) error {
	entry, err := logical.StorageEntryJSON(r.keyPath(name), key)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// LIST /sys/external-keys/configs
func (r *ExternalKeyRegistry) ListConfigs(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	storage := r.storageViewForRequest(req)

	keys, err := storage.List(ctx, r.configListPath())
	if err != nil {
		return handleError(err)
	}

	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name
func (r *ExternalKeyRegistry) GetConfig(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("config").(string)
	storage := r.storageViewForRequest(req)

	config, err := r.getConfigCommon(ctx, storage, name)
	switch {
	case err != nil:
		return handleError(err)
	case config == nil:
		return nil, logical.CodedError(http.StatusNotFound, "config not found")
	}

	resp := &logical.Response{Data: make(map[string]any)}

	// We merge these down into a unified map on the API level.
	switch {
	case config.Type != "":
		resp.Data["type"] = config.Type
	case config.Inherits != "":
		resp.Data["inherits"] = config.Inherits
	}

	for k, v := range config.Values {
		resp.Data[k] = v
	}

	return resp, nil
}

// PUT /sys/external-keys/configs/:config-name
func (r *ExternalKeyRegistry) PutConfig(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	values := make(map[string]string)
	for k, v := range req.Data {
		str, ok := v.(string)
		if !ok {
			return handleError(fmt.Errorf("expected field %q to be a string", k))
		}
		values[k] = str
	}

	// We remove these from the values map and place them in their own dedicated
	// fields. This is not strictly needed, but should make it easy to pass the
	// the remaining values right to the KMS interface.
	ty, inherits := values["type"], values["inherits"]
	delete(values, "type")
	delete(values, "inherits")

	name := data.Get("config").(string)
	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		// Check for an existing config, we may have a conflict e.g. when trying
		// to change a a typed config to an inherited config.
		config, err := r.getConfigCommon(ctx, storage, name)
		if err != nil {
			return err
		}

		// Create a new config if it doesn't exist yet.
		if config == nil {
			config = &ExternalKeyConfig{}
		}

		if err := r.validateConfigTransition(
			config.Type != "", ty != "", config.Inherits != "", inherits != "",
		); err != nil {
			return err
		}

		config.Type = ty
		config.Inherits = inherits
		config.Values = values

		if config.Inherits != "" && len(config.Values) != 0 {
			return fmt.Errorf("setting field %q requires that no other fields are set", "inherits")
		}

		return r.putConfigCommon(ctx, storage, name, config)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// PATCH /sys/external-keys/configs/:config-name
func (r *ExternalKeyRegistry) PatchConfig(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("config").(string)
	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		config, err := r.getConfigCommon(ctx, storage, name)
		switch {
		case err != nil:
			return err
		case config == nil:
			return logical.CodedError(http.StatusNotFound, "config not found")
		}

		// Bit of a hack, but makes patching easier.
		config.Values["type"] = config.Type
		config.Values["inherits"] = config.Inherits

		// This is effectively a JSON merge patch (https://datatracker.ietf.org/doc/html/rfc7386).
		// We could use the json-patch library, but that's overkill for single-level string maps.
		for k, v := range req.Data {
			switch v := v.(type) {
			case string:
				config.Values[k] = v
			case nil:
				delete(config.Values, k)
			default:
				return fmt.Errorf("expected field %q to be a string or null", k)
			}
		}

		ty, inherits := config.Values["type"], config.Values["inherits"]
		delete(config.Values, "type")
		delete(config.Values, "inherits")

		if err := r.validateConfigTransition(
			config.Type != "", ty != "", config.Inherits != "", inherits != "",
		); err != nil {
			return err
		}

		config.Type = ty
		config.Inherits = inherits

		if config.Inherits != "" && len(config.Values) != 0 {
			return fmt.Errorf("setting field %q requires that no other fields are set", "inherits")
		}

		return r.putConfigCommon(ctx, storage, name, config)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// validateConfigTransition enforces the invariants defined below.
func (r *ExternalKeyRegistry) validateConfigTransition(
	// Whether the "type" field was set before the change
	typeBefore bool,
	// Whether the "type" field will be set after the change
	typeAfter bool,
	// Whether the "inherits" field was set before the change
	inheritsBefore bool,
	// Whether the "inherits" field will be set after the change
	inheritsAfter bool,
) error {
	for _, invariant := range externalKeyConfigTransitionInvariants {
		if invariant.cond(typeBefore, typeAfter, inheritsBefore, inheritsAfter) {
			return errors.New(invariant.err)
		}
	}

	return nil
}

// externalKeyConfigTransitionInvariants holds invariants for modifications to
// External Key config entries. There are a few here, but the general idea is
// that a config must be either inherited or "typed", and we can move from an
// inherited config to a typed config, but not the other way.
var externalKeyConfigTransitionInvariants = []struct {
	err  string
	cond func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool
}{
	{
		`the "type" and "inherits" fields are mutually exclusive`,
		func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool {
			return (typeBefore && inheritsBefore) || (typeAfter && inheritsAfter)
		},
	},
	{
		`either the "type" or the "inherits" field must be set`,
		func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool {
			return !typeAfter && !inheritsAfter
		},
	},
	{
		`cannot remove field "type"`,
		func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool {
			return typeBefore && !typeAfter
		},
	},
	{
		`removing field "inherits" requires adding field "type"`,
		func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool {
			return inheritsBefore && !inheritsAfter && !typeAfter
		},
	},
	{
		`adding field "type" requires removing field "inherits"`,
		func(typeBefore, typeAfter, inheritsBefore, inheritsAfter bool) bool {
			return inheritsBefore && inheritsAfter && typeAfter
		},
	},
}

// DELETE /sys/external-keys/configs/:config-name
func (r *ExternalKeyRegistry) DeleteConfig(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("config").(string)
	storage := r.storageViewForRequest(req)

	// We need to lock here to ensure config deletion doesn't race against key
	// creation and leaves a dangling key. Also see comment in PutKey(...).
	r.storageLock.Lock()
	defer r.storageLock.Unlock()

	keysView := logical.NewStorageView(storage, r.keyListPath(name))
	if err := logical.ClearViewWithLogging(ctx, keysView, r.logger); err != nil {
		return handleError(err)
	}

	if err := storage.Delete(ctx, r.configPath(name)); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys
func (r *ExternalKeyRegistry) ListKeys(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("config").(string)
	storage := r.storageViewForRequest(req)

	keys, err := storage.List(ctx, r.keyListPath(name))
	if err != nil {
		return handleError(err)
	}

	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name/keys/:key-name
func (r *ExternalKeyRegistry) GetKey(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := path.Join(data.Get("config").(string), data.Get("key").(string))
	storage := r.storageViewForRequest(req)

	key, err := r.getKeyCommon(ctx, storage, name)
	switch {
	case err != nil:
		return handleError(err)
	case key == nil:
		return nil, logical.CodedError(http.StatusNotFound, "key not found")
	}

	resp := &logical.Response{Data: make(map[string]any)}
	for k, v := range key.Values {
		resp.Data[k] = v
	}

	return resp, nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name
func (r *ExternalKeyRegistry) PutKey(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	values := make(map[string]string)
	for k, v := range req.Data {
		str, ok := v.(string)
		if !ok {
			return handleError(fmt.Errorf("expected field %q to be a string", k))
		}
		values[k] = str
	}

	configName, keyName := data.Get("config").(string), data.Get("key").(string)
	fullName := path.Join(configName, keyName)

	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		key, err := r.getKeyCommon(ctx, storage, fullName)
		if err != nil {
			return err
		}

		// Create a new key if it doesn't exist yet.
		if key == nil {
			// If the corresponding config gets deleted before we create a new
			// key, that wouldn't fail this transaction and we'd create a
			// dangling key. Thus lock within the application. We don't need to
			// do this if the key already exists, since config deletion deletes
			// all its keys first, which _would_ fail the transaction.
			r.storageLock.RLock()
			defer r.storageLock.RUnlock()

			// Ensure that the config we're creating this key in actually exists.
			config, err := r.getConfigCommon(ctx, storage, configName)
			switch {
			case err != nil:
				return err
			case config == nil:
				return logical.CodedError(http.StatusNotFound, "config not found")
			}

			if config.Inherits != "" {
				return fmt.Errorf(
					"cannot create key for inherited config, create it for the original one")
			}

			key = &ExternalKey{
				Grants: []string{}, // For consistency.
			}
		}

		// Update Values, make sure not to override Grants, these should stay
		// if the key already existed.
		key.Values = values

		return r.putKeyCommon(ctx, storage, fullName, key)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// PATCH /sys/external-keys/configs/:config-name/keys/:key-name
func (r *ExternalKeyRegistry) PatchKey(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := path.Join(data.Get("config").(string), data.Get("key").(string))
	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		key, err := r.getKeyCommon(ctx, storage, name)
		switch {
		case err != nil:
			return err
		case key == nil:
			return logical.CodedError(http.StatusNotFound, "key not found")
		}

		// This is effectively a JSON merge patch (https://datatracker.ietf.org/doc/html/rfc7386).
		// We could use the json-patch library, but that's overkill for single-level string maps.
		for k, v := range req.Data {
			switch v := v.(type) {
			case string:
				key.Values[k] = v
			case nil:
				delete(key.Values, k)
			default:
				return fmt.Errorf("expected field %q to be a string or null", k)
			}
		}

		return r.putKeyCommon(ctx, storage, name, key)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name
func (r *ExternalKeyRegistry) DeleteKey(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := path.Join(data.Get("config").(string), data.Get("key").(string))
	storage := r.storageViewForRequest(req)

	if err := storage.Delete(ctx, r.keyPath(name)); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys/:key-name/grants
func (r *ExternalKeyRegistry) ListGrants(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name := path.Join(data.Get("config").(string), data.Get("key").(string))
	storage := r.storageViewForRequest(req)

	key, err := r.getKeyCommon(ctx, storage, name)
	switch {
	case err != nil:
		return handleError(err)
	case key == nil:
		return nil, logical.CodedError(http.StatusNotFound, "key not found")
	}

	return logical.ListResponse(key.Grants), nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (r *ExternalKeyRegistry) PutGrant(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	mount := data.Get("mount").(string)
	name := path.Join(data.Get("config").(string), data.Get("key").(string))

	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		key, err := r.getKeyCommon(ctx, storage, name)
		switch {
		case err != nil:
			return err
		case key == nil:
			return logical.CodedError(http.StatusNotFound, "key not found")
		}

		// Canonicalize the mount path; both for comparison with other paths and
		// to get a consistent representation for display.
		mount = strings.Trim(mount, "/") + "/"

		if slices.Contains(key.Grants, mount) {
			return nil
		}

		key.Grants = append(key.Grants, mount)

		return r.putKeyCommon(ctx, storage, name, key)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (r *ExternalKeyRegistry) DeleteGrant(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	mount := data.Get("mount").(string)
	name := path.Join(data.Get("config").(string), data.Get("key").(string))

	storage := r.storageViewForRequest(req)

	if err := logical.WithTransaction(ctx, storage, func(storage logical.Storage) error {
		key, err := r.getKeyCommon(ctx, storage, name)
		switch {
		case err != nil:
			return err
		case key == nil:
			return logical.CodedError(http.StatusNotFound, "key not found")
		}

		// Canonicalize the mount path; both for comparison with other paths and
		// to get a consistent representation for display.
		mount = strings.Trim(mount, "/") + "/"

		if !slices.Contains(key.Grants, mount) {
			return nil
		}

		key.Grants = slices.DeleteFunc(key.Grants, func(grant string) bool {
			return grant == mount
		})

		return r.putKeyCommon(ctx, storage, name, key)
	}); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (r *ExternalKeyRegistry) Finalize() {}
