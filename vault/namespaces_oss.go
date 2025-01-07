// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	return namespaceByID(ctx, nsID, c)
}

func (c *Core) ListNamespaces(includePath bool) []*namespace.Namespace {
	return []*namespace.Namespace{namespace.RootNamespace}
}

func (c *Core) resetNamespaceCache() {}

// start all new namespace code below

const (
	// namspaceSubPath is the sub-path used for the namespace store view. This is
	// nested under the system view.
	namespaceSubPath = "namespaces/"
)

var immutableNamespaces = []string{
	"sys",
	"audit",
	"auth",
	"cubbyhole",
	"identity",
}

func (b *SystemBackend) namespacePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: namespaceSubPath + "?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "list",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesList(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
								"namespaces": {
									Type: framework.TypeStringSlice,
								},
							},
						}},
					},
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleNamespacesList(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
								"namespaces": {
									Type: framework.TypeStringSlice,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespace-list"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespace-list"][1]),
		},

		{
			Pattern: namespaceSubPath + "(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				// OperationSuffix: "api-namespace2", // ??? this endpoint duplicates /sys/namespaces/api-lock
			},

			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: strings.TrimSpace(sysHelp["namespace-id"][0]),
				},
				"path": {
					Type:        framework.TypeString,
					Description: strings.TrimSpace(sysHelp["namespace-path"][0]),
				},
				"custom_metadata": {
					Type:        framework.TypeMap,
					Description: strings.TrimSpace(sysHelp["namespace-custom_metadata"][0]),
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"id": {
									Type:     framework.TypeString,
									Required: false,
								},
								"path": {
									Type:     framework.TypeString,
									Required: true,
								},
								"custom_metadata": {
									Type:     framework.TypeMap,
									Required: false,
								},
							},
						}},
					},
					Summary: "Retrieve the namespace body for the named path.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesSet(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Add a new namespace.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleNamespacesPatch(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Update an existing namespace.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespacesDelete(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Delete the namespace with the given name.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespace"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespace"][1]),
		},
	}
}

// handleNamespacesList handles /sys/namespaces/ endpoints to provide the enabled namespaces
func (b *SystemBackend) handleNamespacesList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		namespaces, err := b.Core.namespaceStore.ListNamespaces(ctx)
		if err != nil {
			return nil, err
		}

		return logical.ListResponse(namespaces), nil
	}
}

// handleNamespacesRead handles the "/sys/namespaces/<path>" endpoints to read a namespace
func (b *SystemBackend) handleNamespacesRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		ns, err := b.Core.namespaceStore.GetNamespace(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, nil
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"id":              ns.ID,
				"path":            ns.Path,
				"custom_metadata": ns.CustomMetadata,
			},
		}

		return resp, nil
	}
}

// handleNamespaceSet handles the "/sys/namespaces/<path>" endpoint to set a namespace
func (b *SystemBackend) handleNamespacesSet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		imetadata, ok := data.GetOk("custom_metadata")
		var metadata map[string]string
		if ok {
			metadata = make(map[string]string)
			for k, v := range imetadata.(map[string]interface{}) {
				if metadata[k], ok = v.(string); !ok {
					return nil, fmt.Errorf("custom_metadata values must be strings")
				}
			}
		}

		// Update the namespace
		if err := b.Core.namespaceStore.SetNamespace(ctx, path, metadata); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesPatch handles the "/sys/namespace/<path>" endpoints to update a namespace
func (b *SystemBackend) handleNamespacesPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		imetadata, ok := data.GetOk("custom_metadata")
		var metadata map[string]string
		if ok {
			metadata = imetadata.(map[string]string)
		}

		// Update the namespace
		if err := b.Core.namespaceStore.PatchNamespace(ctx, path, metadata); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

func (b *SystemBackend) handleNamespacesDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		if err := b.Core.namespaceStore.DeleteNamespace(ctx, path); err != nil {
			return handleError(err)
		}
		return nil, nil
	}
}

// NamespaceStore is used to provide durable storage of namespace
type NamespaceStore struct {
	core    *Core
	aclView BarrierView

	// This is used to ensure that writes to the store (acl) or to the egp
	// path tree don't happen concurrently. We are okay reading stale data so
	// long as there aren't concurrent writes.
	modifyLock *sync.RWMutex

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NamespaceEntry is used to store a namespace by name
type NamespaceEntry struct {
	namespace.Namespace
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, baseView BarrierView, system logical.SystemView, logger hclog.Logger) (*NamespaceStore, error) {
	ps := &NamespaceStore{
		aclView:    baseView.SubView(namespaceSubPath),
		modifyLock: new(sync.RWMutex),
		logger:     logger,
		core:       core,
	}

	// initialize the namespace store to have the root namespace
	err := ps.SetNamespace(ctx, namespace.RootNamespaceID, map[string]string{}, true)
	return ps, err
}

// setupNamespaceStore is used to initialize the namespace store
// when the vault is being unsealed.
func (c *Core) setupNamespaceStore(ctx context.Context) error {
	// Create the Namespace store
	var err error
	sysView := &dynamicSystemView{core: c}
	psLogger := c.baseLogger.Named("namespace")
	c.AddLogger(psLogger)
	c.namespaceStore, err = NewNamespaceStore(ctx, c, c.systemBarrierView, sysView, psLogger)

	return err
}

// teardownNamespaceStore is used to reverse setupNamespaceStore
// when the vault is being sealed.
func (c *Core) teardownNamespaceStore() error {
	c.namespaceStore = nil
	return nil
}

func (ps *NamespaceStore) invalidate(ctx context.Context, path string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	if ns == nil {
		return fmt.Errorf("namespace not found in context")
	}
	if err = ps.DeleteNamespace(ctx, path); err != nil {
		return err
	}

	ps = nil
	return nil
}

// SetNamespace is used to create or update a given namespace
func (ps *NamespaceStore) SetNamespace(ctx context.Context, path string, meta map[string]string, init ...bool) error {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace"}, time.Now())

	if path == "" {
		return fmt.Errorf("path name missing")
	}

	// Namespaces are normalized to lower-case
	path = ps.sanitizeName(path)
	if strutil.StrListContains(immutableNamespaces, path) || strings.Contains(path, "/") {
		return fmt.Errorf("cannot update %q namespace", path)
	}

	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	// Get the appropriate view
	view := ps.aclView
	if view == nil {
		return fmt.Errorf("unable to get the barrier subview for namespace")
	}

	if init == nil && path == namespace.RootNamespaceID {
		return fmt.Errorf(`cannot update "root" namespace`)
	}

	// Create the entry
	entry, err := logical.StorageEntryJSON(path, &namespace.Namespace{
		ID:             path,
		CustomMetadata: meta,
	})
	if err != nil {
		return fmt.Errorf("failed to create entry for namespace: %w", err)
	}

	if err := view.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to put new namespace to %s: %w", path, err)
	}

	return nil
}

// PatchNamespace is used to update the given namespace
func (ps *NamespaceStore) PatchNamespace(ctx context.Context, path string, meta map[string]string) error {
	return fmt.Errorf("namespace patching is not supported, use the delete and set operation instead")
}

// GetNamespace is used to fetch the named namespace
func (ps *NamespaceStore) GetNamespace(ctx context.Context, name string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	// Namespaces are normalized to lower-case
	name = ps.sanitizeName(name)
	// Get the appropriate view
	view := ps.aclView
	if view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for namespace")
	}

	out, err := view.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read namespace: %w", err)
	}
	if out == nil {
		return nil, nil
	}
	namespaceEntry := new(namespace.Namespace)
	err = out.DecodeJSON(namespaceEntry)

	return namespaceEntry, err
}

// ListNamespaces is used to list the available namespaces
func (ps *NamespaceStore) ListNamespaces(ctx context.Context) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	// Get the appropriate view
	view := ps.aclView
	if view == nil {
		return []string{}, fmt.Errorf("unable to get the barrier subview for namespace")
	}

	return logical.CollectKeys(ctx, view)
}

// DeleteNamespace is used to delete the named namespace
func (ps *NamespaceStore) DeleteNamespace(ctx context.Context, path string) error {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	// Namespaces are normalized to lower-case
	path = ps.sanitizeName(path)
	view := ps.aclView
	if view == nil {
		return fmt.Errorf("unable to get the barrier subview for namespace")
	}

	if strutil.StrListContains(immutableNamespaces, path) || strings.Contains(path, "/") {
		return fmt.Errorf("cannot delete %q namespace", path)
	}

	if path == namespace.RootNamespaceID {
		return fmt.Errorf(`cannot delete "root" namespace`)
	}

	if err := view.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to delete namespace: %w", err)
	}

	return nil
}

func (ps *NamespaceStore) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
