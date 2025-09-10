// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/storagepacker"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"zgo.at/zcache/v2"
)

const (
	groupBucketsPrefix        = "packer/group/buckets/"
	localAliasesBucketsPrefix = "packer/local-aliases/buckets/"
)

var (
	caseSensitivityKey           = "casesensitivity"
	parseExtraEntityFromBucket   = func(context.Context, *IdentityStore, *identity.Entity) (bool, error) { return false, nil }
	addExtraEntityDataToResponse = func(*identity.Entity, map[string]interface{}) {}
)

func (c *Core) IdentityStore() *IdentityStore {
	return c.identityStore
}

func (i *IdentityStore) resetDB(ctx context.Context) error {
	var err error

	i.views.Range(func(uuidRaw, viewsRaw any) bool {
		uuid := uuidRaw.(string)
		views := viewsRaw.(*identityStoreNamespaceView)

		views.db, err = memdb.NewMemDB(identityStoreSchema(!i.disableLowerCasedNames))
		if err != nil {
			err = fmt.Errorf("error resetting database for namespace %v: %w", uuid, err)
			return false
		}

		return true
	})

	return err
}

func NewIdentityStore(ctx context.Context, core *Core, config *logical.BackendConfig, logger log.Logger) (*IdentityStore, error) {
	iStore := &IdentityStore{
		logger:        logger,
		router:        core.router,
		redirectAddr:  core.redirectAddr,
		localNode:     core,
		namespacer:    core,
		metrics:       core.MetricSink(),
		totpPersister: core,
		tokenStorer:   core,
		mfaBackend:    core.loginMFABackend,
	}

	if err := iStore.AddNamespaceView(core, namespace.RootNamespace, config.StorageView); err != nil {
		return nil, err
	}

	iStore.Backend = &framework.Backend{
		BackendType:    logical.TypeLogical,
		Paths:          iStore.paths(),
		Invalidate:     iStore.Invalidate,
		InitializeFunc: iStore.initialize,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"oidc/.well-known/*",
				"oidc/provider/+/.well-known/*",
				"oidc/provider/+/token",
			},
			LocalStorage: []string{
				localAliasesBucketsPrefix,
			},
		},
		PeriodicFunc: func(ctx context.Context, req *logical.Request) error {
			iStore.oidcPeriodicFunc(ctx)

			return nil
		},
		RunningVersion: versions.DefaultBuiltinVersion,
	}

	iStore.oidcCache = newOIDCCache(zcache.NoExpiration, zcache.NoExpiration)
	iStore.oidcAuthCodeCache = newOIDCCache(5*time.Minute, 5*time.Minute)

	if err := iStore.Setup(ctx, config); err != nil {
		return nil, err
	}

	return iStore, nil
}

func (i *IdentityStore) AddNamespaceView(core *Core, ns *namespace.Namespace, view logical.Storage) error {
	nsView := &identityStoreNamespaceView{
		view: view,
	}

	// Create loggers for packers
	entitiesPackerLogger := i.logger.Named("storagepacker").Named("entities")
	core.AddLogger(entitiesPackerLogger)

	localAliasesPackerLogger := i.logger.Named("storagepacker").Named("local-aliases")
	core.AddLogger(localAliasesPackerLogger)

	groupsPackerLogger := i.logger.Named("storagepacker").Named("groups")
	core.AddLogger(groupsPackerLogger)

	// Create packers for namespace.
	var err error
	nsView.entityPacker, err = storagepacker.NewStoragePacker(nsView.view, entitiesPackerLogger, "")
	if err != nil {
		return fmt.Errorf("failed to create entity packer: %w", err)
	}

	nsView.localAliasPacker, err = storagepacker.NewStoragePacker(nsView.view, localAliasesPackerLogger, localAliasesBucketsPrefix)
	if err != nil {
		return fmt.Errorf("failed to create local alias packer: %w", err)
	}

	nsView.groupPacker, err = storagepacker.NewStoragePacker(nsView.view, groupsPackerLogger, groupBucketsPrefix)
	if err != nil {
		return fmt.Errorf("failed to create group packer: %w", err)
	}

	if ns.ID == namespace.RootNamespaceID || !core.unsafeCrossNamespaceIdentity {
		nsView.db, err = memdb.NewMemDB(identityStoreSchema(!i.disableLowerCasedNames))
		if err != nil {
			return err
		}
	}

	i.views.Store(ns.UUID, nsView)

	return nil
}

func (i *IdentityStore) RemoveNamespaceView(ns *namespace.Namespace) error {
	if ns.ID == namespace.RootNamespaceID {
		return fmt.Errorf("refusing to remove root namespace from identity store")
	}

	view, ok := i.views.Load(ns.UUID)
	if ok && view.(*identityStoreNamespaceView).db == nil {
		rootView, ok := i.views.Load(namespace.RootNamespaceUUID)
		if !ok {
			return fmt.Errorf("failed to get root namespace db")
		}

		// Clean up all memdb entries associated with the namespace.
		if err := func() error {
			db := rootView.(*identityStoreNamespaceView).db
			txn := db.Txn(true)
			defer txn.Commit()

			for _, table := range []string{entityAliasesTable, entitiesTable, groupsTable, groupAliasesTable, oidcClientsTable} {
				if _, err := txn.DeleteAll(table, "namespace_id", ns.ID); err != nil {
					return fmt.Errorf("failed to clean up %v: %w", table, err)
				}
			}

			return nil
		}(); err != nil {
			return fmt.Errorf("failed to cleanup identity store: %w", err)
		}
	}

	i.views.Delete(ns.UUID)

	if err := i.oidcCache.Flush(ns); err != nil {
		return fmt.Errorf("failed to flush oidcCache: %w", err)
	}

	if err := i.oidcAuthCodeCache.Flush(ns); err != nil {
		return fmt.Errorf("failed to flush oidcAuthCodeCache: %w", err)
	}

	return nil
}

func (i *IdentityStore) validateCtx(ctx context.Context) error {
	_, err := i.getNSView(ctx)
	return err
}

func (i *IdentityStore) getNSView(ctx context.Context) (*identityStoreNamespaceView, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	view, ok := i.views.Load(ns.UUID)
	if !ok {
		return nil, fmt.Errorf("namespace %v missing from identity store table", ns.UUID)
	}

	return view.(*identityStoreNamespaceView), nil
}

func (i *IdentityStore) view(ctx context.Context) logical.Storage {
	view, err := i.getNSView(ctx)
	if err != nil {
		i.logger.Error("failed to get view", "err", err)
		return nil
	}

	return view.view
}

func (i *IdentityStore) entityPacker(ctx context.Context) *storagepacker.StoragePacker {
	view, err := i.getNSView(ctx)
	if err != nil {
		i.logger.Error("failed to get entityPacker", "err", err)
		return nil
	}

	return view.entityPacker
}

func (i *IdentityStore) localAliasPacker(ctx context.Context) *storagepacker.StoragePacker {
	view, err := i.getNSView(ctx)
	if err != nil {
		i.logger.Error("failed to get localAliasPacker", "err", err)
		return nil
	}

	return view.localAliasPacker
}

func (i *IdentityStore) groupPacker(ctx context.Context) *storagepacker.StoragePacker {
	view, err := i.getNSView(ctx)
	if err != nil {
		i.logger.Error("failed to get groupPacker", "err", err)
		return nil
	}

	return view.groupPacker
}

func (i *IdentityStore) db(ctx context.Context) *memdb.MemDB {
	view, err := i.getNSView(ctx)
	if err != nil {
		i.logger.Error("failed to get db", "err", err)
		return nil
	}

	if view.db == nil {
		rootView, ok := i.views.Load(namespace.RootNamespaceUUID)
		if !ok || rootView == nil {
			i.logger.Error("failed to get root namespace db")
			return nil
		}

		return rootView.(*identityStoreNamespaceView).db
	}

	return view.db
}

func (i *IdentityStore) paths() []*framework.Path {
	return framework.PathAppend(
		entityPaths(i),
		aliasPaths(i),
		groupAliasPaths(i),
		groupPaths(i),
		lookupPaths(i),
		upgradePaths(i),
		oidcPaths(i),
		oidcProviderPaths(i),
		mfaPaths(i),
	)
}

func mfaPaths(i *IdentityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "mfa/method" + genericOptionalUUIDRegex("method_id"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "read",
				OperationSuffix: "method-configuration|method-configuration",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodReadGlobal,
					Summary:  "Read the current configuration for the given ID regardless of the MFA method type",
				},
			},
		},
		{
			Pattern: "mfa/method/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "list",
				OperationSuffix: "methods",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodListGlobal,
					Summary:  "List MFA method configurations for all MFA methods",
				},
			},
		},
		{
			Pattern: "mfa/method/totp" + genericOptionalUUIDRegex("method_id"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_name": {
					Type:        framework.TypeString,
					Description: `The unique name identifier for this MFA method.`,
				},
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
				},
				"max_validation_attempts": {
					Type:        framework.TypeInt,
					Description: `Max number of allowed validation attempts.`,
				},
				"issuer": {
					Type:        framework.TypeString,
					Description: `The name of the key's issuing organization.`,
				},
				"period": {
					Type:        framework.TypeDurationSecond,
					Default:     30,
					Description: `The length of time used to generate a counter for the TOTP token calculation.`,
				},
				"key_size": {
					Type:        framework.TypeInt,
					Default:     20,
					Description: "Determines the size in bytes of the generated key.",
				},
				"qr_size": {
					Type:        framework.TypeInt,
					Default:     200,
					Description: `The pixel size of the generated square QR code.`,
				},
				"algorithm": {
					Type:        framework.TypeString,
					Default:     "SHA1",
					Description: `The hashing algorithm used to generate the TOTP token. Options include SHA1, SHA256 and SHA512.`,
				},
				"digits": {
					Type:        framework.TypeInt,
					Default:     6,
					Description: `The number of digits in the generated TOTP token. This value can either be 6 or 8.`,
				},
				"skew": {
					Type:        framework.TypeInt,
					Default:     1,
					Description: `The number of delay periods that are allowed when validating a TOTP token. This value can either be 0 or 1.`,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodTOTPRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "totp-method-configuration|totp-method-configuration",
					},
					Summary: "Read the current configuration for the given MFA method",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodTOTPUpdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "totp-method|totp-method",
					},
					Summary: "Update or create a configuration for the given MFA method",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodTOTPDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete",
						OperationSuffix: "totp-method|totp-method",
					},
					Summary: "Delete a configuration for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/totp/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "list",
				OperationSuffix: "totp-methods",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodListTOTP,
					Summary:  "List MFA method configurations for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/totp/generate$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "generate",
				OperationSuffix: "totp-secret",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleLoginMFAGenerateUpdate,
					Summary:  "Update or create TOTP secret for the given method ID on the given entity.",
				},
			},
		},
		{
			Pattern: "mfa/method/totp/admin-generate$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "admin-generate",
				OperationSuffix: "totp-secret",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
					Required:    true,
				},
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID on which the generated secret needs to get stored.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleLoginMFAAdminGenerateUpdate,
					Summary:  "Update or create TOTP secret for the given method ID on the given entity.",
				},
			},
		},
		{
			Pattern: "mfa/method/totp/admin-destroy$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationVerb:   "admin-destroy",
				OperationSuffix: "totp-secret",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_id": {
					Type:        framework.TypeString,
					Description: "The unique identifier for this MFA method.",
					Required:    true,
				},
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Identifier of the entity from which the MFA method secret needs to be removed.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleLoginMFAAdminDestroyUpdate,
					Summary:  "Destroys a TOTP secret for the given MFA method ID on the given entity",
				},
			},
		},
		{
			Pattern: "mfa/method/okta" + genericOptionalUUIDRegex("method_id"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_name": {
					Type:        framework.TypeString,
					Description: `The unique name identifier for this MFA method.`,
				},
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
				},
				"username_format": {
					Type:        framework.TypeString,
					Description: `A template string for mapping Identity names to MFA method names. Values to substitute should be placed in {{}}. For example, "{{entity.name}}@example.com". If blank, the Entity's name field will be used as-is.`,
				},
				"org_name": {
					Type:        framework.TypeString,
					Description: "Name of the organization to be used in the Okta API.",
				},
				"api_token": {
					Type:        framework.TypeString,
					Description: "Okta API key.",
				},
				"base_url": {
					Type:        framework.TypeString,
					Description: `The base domain to use for the Okta API. When not specified in the configuration, "okta.com" is used.`,
				},
				"primary_email": {
					Type:        framework.TypeBool,
					Description: `If true, the username will only match the primary email for the account. Defaults to false.`,
				},
				"production": {
					Type:        framework.TypeBool,
					Description: "(DEPRECATED) Use base_url instead.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodOKTARead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "okta-method-configuration|okta-method-configuration",
					},
					Summary: "Read the current configuration for the given MFA method",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodOKTAUpdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "okta-method|okta-method",
					},
					Summary: "Update or create a configuration for the given MFA method",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodOKTADelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete",
						OperationSuffix: "okta-method|okta-method",
					},
					Summary: "Delete a configuration for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/okta/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodListOkta,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "mfa",
						OperationVerb:   "list",
						OperationSuffix: "okta-methods",
					},
					Summary: "List MFA method configurations for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/duo" + genericOptionalUUIDRegex("method_id"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_name": {
					Type:        framework.TypeString,
					Description: `The unique name identifier for this MFA method.`,
				},
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
				},
				"username_format": {
					Type:        framework.TypeString,
					Description: `A template string for mapping Identity names to MFA method names. Values to subtitute should be placed in {{}}. For example, "{{alias.name}}@example.com". Currently-supported mappings: alias.name: The name returned by the mount configured via the mount_accessor parameter If blank, the Alias's name field will be used as-is. `,
				},
				"secret_key": {
					Type:        framework.TypeString,
					Description: "Secret key for Duo.",
				},
				"integration_key": {
					Type:        framework.TypeString,
					Description: "Integration key for Duo.",
				},
				"api_hostname": {
					Type:        framework.TypeString,
					Description: "API host name for Duo.",
				},
				"push_info": {
					Type:        framework.TypeString,
					Description: "Push information for Duo.",
				},
				"use_passcode": {
					Type:        framework.TypeBool,
					Description: `If true, the user is reminded to use the passcode upon MFA validation. This option does not enforce using the passcode. Defaults to false.`,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodDuoRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "duo-method-configuration|duo-method-configuration",
					},
					Summary: "Read the current configuration for the given MFA method",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodDuoUpdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "duo-method|duo-method",
					},
					Summary: "Update or create a configuration for the given MFA method",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodDUODelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete",
						OperationSuffix: "duo-method|duo-method",
					},
					Summary: "Delete a configuration for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/duo/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodListDuo,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "mfa",
						OperationVerb:   "list",
						OperationSuffix: "duo-methods",
					},
					Summary: "List MFA method configurations for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/pingid" + genericOptionalUUIDRegex("method_id"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
			},
			Fields: map[string]*framework.FieldSchema{
				"method_name": {
					Type:        framework.TypeString,
					Description: `The unique name identifier for this MFA method.`,
				},
				"method_id": {
					Type:        framework.TypeString,
					Description: `The unique identifier for this MFA method.`,
				},
				"username_format": {
					Type:        framework.TypeString,
					Description: `A template string for mapping Identity names to MFA method names. Values to subtitute should be placed in {{}}. For example, "{{alias.name}}@example.com". Currently-supported mappings: alias.name: The name returned by the mount configured via the mount_accessor parameter If blank, the Alias's name field will be used as-is. `,
				},
				"settings_file_base64": {
					Type:        framework.TypeString,
					Description: "The settings file provided by Ping, Base64-encoded. This must be a settings file suitable for third-party clients, not the PingID SDK or PingFederate.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodPingIDRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "ping-id-method-configuration|ping-id-method-configuration",
					},
					Summary: "Read the current configuration for the given MFA method",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodPingIDUpdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "ping-id-method|ping-id-method",
					},
					Summary: "Update or create a configuration for the given MFA method",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodPingIDDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete",
						OperationSuffix: "ping-id-method|ping-id-method",
					},
					Summary: "Delete a configuration for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/method/pingid/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFAMethodListPingID,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "mfa",
						OperationVerb:   "list",
						OperationSuffix: "ping-id-methods",
					},
					Summary: "List MFA method configurations for the given MFA method",
				},
			},
		},
		{
			Pattern: "mfa/login-enforcement/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationSuffix: "login-enforcement",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name for this login enforcement configuration",
					Required:    true,
				},
				"mfa_method_ids": {
					Type:        framework.TypeStringSlice,
					Description: "Array of Method IDs that determine what methods will be enforced",
					Required:    true,
				},
				"auth_method_accessors": {
					Type:        framework.TypeStringSlice,
					Description: "Array of auth mount accessor IDs",
				},
				"auth_method_types": {
					Type:        framework.TypeStringSlice,
					Description: "Array of auth mount types",
				},
				"identity_group_ids": {
					Type:        framework.TypeStringSlice,
					Description: "Array of identity group IDs",
				},
				"identity_entity_ids": {
					Type:        framework.TypeStringSlice,
					Description: "Array of identity entity IDs",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: i.handleMFALoginEnforcementRead,
					Summary:  "Read the current login enforcement",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: i.handleMFALoginEnforcementUpdate,
					Summary:  "Create or update a login enforcement",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: i.handleMFALoginEnforcementDelete,
					Summary:  "Delete a login enforcement",
				},
			},
		},
		{
			Pattern: "mfa/login-enforcement/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "mfa",
				OperationSuffix: "login-enforcements",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: i.handleMFALoginEnforcementList,
					Summary:  "List login enforcements",
				},
			},
		},
	}
}

func (i *IdentityStore) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	if err := i.storeOIDCDefaultResources(ctx, req.Storage); err != nil {
		i.logger.Error("failed to write OIDC default resources to storage", "error", err)
		return err
	}

	// if the storage entry for caseSensitivityKey exists, remove it
	storageEntry, err := i.view(ctx).Get(ctx, caseSensitivityKey)
	if err != nil {
		i.logger.Error("could not get storage entry for case sensitivity key", "error", err)
		return nil
	}

	if storageEntry != nil {
		var setting casesensitivity
		err := storageEntry.DecodeJSON(&setting)
		switch err {
		case nil:
			i.logger.Debug("removing storage entry for case sensitivity key", "value", setting.DisableLowerCasedNames)
		default:
			i.logger.Error("failed to decode case sensitivity key, removing its storage entry anyway", "error", err)
		}

		err = i.view(ctx).Delete(ctx, caseSensitivityKey)
		if err != nil {
			i.logger.Error("could not delete storage entry for case sensitivity key", "error", err)
			return nil
		}
	}

	return nil
}

// Invalidate is a callback wherein the backend is informed that the value at
// the given key is updated. In identity store's case, it would be the entity
// storage entries that get updated. The value needs to be read and MemDB needs
// to be updated accordingly.
func (i *IdentityStore) Invalidate(ctx context.Context, key string) {
	i.logger.Debug("invalidate notification received", "key", key)

	i.lock.Lock()
	defer i.lock.Unlock()

	if err := i.validateCtx(ctx); err != nil {
		i.logger.Error("got invalidation for unknown namespace", "err", err)
		return
	}

	switch {
	// Check if the key is a storage entry key for an entity bucket
	case strings.HasPrefix(key, storagepacker.StoragePackerBucketsPrefix):
		// Create a MemDB transaction
		txn := i.db(ctx).Txn(true)
		defer txn.Abort()

		// Each entity object in MemDB holds the MD5 hash of the storage
		// entry key of the entity bucket. Fetch all the entities that
		// belong to this bucket using the hash value. Remove these entities
		// from MemDB along with all the aliases of each entity.
		entitiesFetched, err := i.MemDBEntitiesByBucketKeyInTxn(txn, key)
		if err != nil {
			i.logger.Error("failed to fetch entities using the bucket key", "key", key)
			return
		}

		for _, entity := range entitiesFetched {
			// Delete all the aliases in the entity. This function will also remove
			// the corresponding alias indexes too.
			err = i.deleteAliasesInEntityInTxn(txn, entity, entity.Aliases)
			if err != nil {
				i.logger.Error("failed to delete aliases in entity", "entity_id", entity.ID, "error", err)
				return
			}

			// Delete the entity using the same transaction
			err = i.MemDBDeleteEntityByIDInTxn(txn, entity.ID)
			if err != nil {
				i.logger.Error("failed to delete entity from MemDB", "entity_id", entity.ID, "error", err)
				return
			}
		}

		// Get the storage bucket entry
		bucket, err := i.entityPacker(ctx).GetBucket(ctx, key)
		if err != nil {
			i.logger.Error("failed to refresh entities", "key", key, "error", err)
			return
		}

		// If the underlying entry is nil, it means that this invalidation
		// notification is for the deletion of the underlying storage entry. At
		// this point, since all the entities belonging to this bucket are
		// already removed, there is nothing else to be done. But, if the
		// storage entry is non-nil, its an indication of an update. In this
		// case, entities in the updated bucket needs to be reinserted into
		// MemDB.
		var entityIDs []string
		if bucket != nil {
			entityIDs = make([]string, 0, len(bucket.Items))
			for _, item := range bucket.Items {
				entity, err := i.parseEntityFromBucketItem(ctx, item)
				if err != nil {
					i.logger.Error("failed to parse entity from bucket entry item", "error", err)
					return
				}

				localAliases, err := i.parseLocalAliases(ctx, entity.ID)
				if err != nil {
					i.logger.Error("failed to load local aliases from storage", "error", err)
					return
				}
				if localAliases != nil {
					for _, alias := range localAliases.Aliases {
						entity.UpsertAlias(alias)
					}
				}

				// Only update MemDB and don't touch the storage
				err = i.upsertEntityInTxn(ctx, txn, entity, nil, false)
				if err != nil {
					i.logger.Error("failed to update entity in MemDB", "error", err)
					return
				}

				entityIDs = append(entityIDs, entity.ID)
			}
		}

		txn.Commit()
		return

	// Check if the key is a storage entry key for an group bucket
	// For those entities that are deleted, clear up the local alias entries
	case strings.HasPrefix(key, groupBucketsPrefix):
		// Create a MemDB transaction
		txn := i.db(ctx).Txn(true)
		defer txn.Abort()

		groupsFetched, err := i.MemDBGroupsByBucketKeyInTxn(txn, key)
		if err != nil {
			i.logger.Error("failed to fetch groups using the bucket key", "key", key)
			return
		}

		for _, group := range groupsFetched {
			// Delete the group using the same transaction
			err = i.MemDBDeleteGroupByIDInTxn(txn, group.ID)
			if err != nil {
				i.logger.Error("failed to delete group from MemDB", "group_id", group.ID, "error", err)
				return
			}

			if group.Alias != nil {
				err := i.MemDBDeleteAliasByIDInTxn(txn, group.Alias.ID, true)
				if err != nil {
					i.logger.Error("failed to delete group alias from MemDB", "error", err)
					return
				}
			}
		}

		// Get the storage bucket entry
		bucket, err := i.groupPacker(ctx).GetBucket(ctx, key)
		if err != nil {
			i.logger.Error("failed to refresh group", "key", key, "error", err)
			return
		}

		if bucket != nil {
			for _, item := range bucket.Items {
				group, err := i.parseGroupFromBucketItem(ctx, item)
				if err != nil {
					i.logger.Error("failed to parse group from bucket entry item", "error", err)
					return
				}

				// Before updating the group, check if the group exists. If it
				// does, then delete the group alias from memdb, for the
				// invalidation would have sent an update.
				groupFetched, err := i.MemDBGroupByIDInTxn(txn, group.ID, true)
				if err != nil {
					i.logger.Error("failed to fetch group from MemDB", "error", err)
					return
				}

				// If the group has an alias remove it from memdb
				if groupFetched != nil && groupFetched.Alias != nil {
					err := i.MemDBDeleteAliasByIDInTxn(txn, groupFetched.Alias.ID, true)
					if err != nil {
						i.logger.Error("failed to delete old group alias from MemDB", "error", err)
						return
					}
				}

				// Only update MemDB and don't touch the storage
				err = i.UpsertGroupInTxn(ctx, txn, group, false)
				if err != nil {
					i.logger.Error("failed to update group in MemDB", "error", err)
					return
				}
			}
		}

		txn.Commit()
		return

	case strings.HasPrefix(key, oidcTokensPrefix):
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			i.logger.Error("error retrieving namespace", "error", err)
			return
		}

		// Wipe the cache for the requested namespace. This will also clear
		// the shared namespace as well.
		if err := i.oidcCache.Flush(ns); err != nil {
			i.logger.Error("error flushing oidc cache", "error", err)
		}
	case strings.HasPrefix(key, clientPath):
		name := strings.TrimPrefix(key, clientPath)

		// Invalidate the cached client in memdb
		if err := i.memDBDeleteClientByName(ctx, name); err != nil {
			i.logger.Error("error invalidating client", "error", err, "key", key)
			return
		}
	case strings.HasPrefix(key, localAliasesBucketsPrefix):
		//
		// This invalidation only happens on perf standbys
		//

		txn := i.db(ctx).Txn(true)
		defer txn.Abort()

		// Find all the local aliases belonging to this bucket and remove it
		// both from aliases table and entities table. We will add the local
		// aliases back by parsing the storage key. This way the deletion
		// invalidation gets handled.
		aliases, err := i.MemDBLocalAliasesByBucketKeyInTxn(txn, key)
		if err != nil {
			i.logger.Error("failed to fetch entities using the bucket key", "key", key)
			return
		}

		for _, alias := range aliases {
			entity, err := i.MemDBEntityByIDInTxn(txn, alias.CanonicalID, true)
			if err != nil {
				i.logger.Error("failed to fetch entity during local alias invalidation", "entity_id", alias.CanonicalID, "error", err)
				return
			}
			if entity == nil {
				i.logger.Error("failed to fetch entity during local alias invalidation, missing entity", "entity_id", alias.CanonicalID, "error", err)
				continue
			}

			// Delete local aliases from the entity.
			err = i.deleteAliasesInEntityInTxn(txn, entity, []*identity.Alias{alias})
			if err != nil {
				i.logger.Error("failed to delete aliases in entity", "entity_id", entity.ID, "error", err)
				return
			}

			// Update the entity with removed alias.
			if err := i.MemDBUpsertEntityInTxn(txn, entity); err != nil {
				i.logger.Error("failed to delete entity from MemDB", "entity_id", entity.ID, "error", err)
				return
			}
		}

		// Now read the invalidated storage key
		bucket, err := i.localAliasPacker(ctx).GetBucket(ctx, key)
		if err != nil {
			i.logger.Error("failed to refresh local aliases", "key", key, "error", err)
			return
		}
		if bucket != nil {
			for _, item := range bucket.Items {
				if strings.HasSuffix(item.ID, tmpSuffix) {
					continue
				}

				var localAliases identity.LocalAliases
				err = item.Message.UnmarshalTo(&localAliases)
				if err != nil {
					i.logger.Error("failed to parse local aliases during invalidation", "error", err)
					return
				}
				for _, alias := range localAliases.Aliases {
					// Add to the aliases table
					if err := i.MemDBUpsertAliasInTxn(txn, alias, false); err != nil {
						i.logger.Error("failed to insert local alias to memdb during invalidation", "error", err)
						return
					}

					// Fetch the associated entity and add the alias to that too.
					entity, err := i.MemDBEntityByIDInTxn(txn, alias.CanonicalID, true)
					if err != nil {
						i.logger.Error("failed to fetch entity during local alias invalidation", "error", err)
						return
					}
					if entity == nil {
						cachedEntityItem, err := i.localAliasPacker(ctx).GetItem(alias.CanonicalID + tmpSuffix)
						if err != nil {
							i.logger.Error("failed to fetch cached entity", "key", key, "error", err)
							return
						}
						if cachedEntityItem != nil {
							entity, err = i.parseCachedEntity(cachedEntityItem)
							if err != nil {
								i.logger.Error("failed to parse cached entity", "key", key, "error", err)
								return
							}
						}
					}
					if entity == nil {
						i.logger.Error("received local alias invalidation for an invalid entity", "item.ID", item.ID)
						return
					}
					entity.UpsertAlias(alias)

					// Update the entities table
					if err := i.MemDBUpsertEntityInTxn(txn, entity); err != nil {
						i.logger.Error("failed to upsert entity during local alias invalidation", "error", err)
						return
					}
				}
			}
		}
		txn.Commit()
		return
	}
}

func (i *IdentityStore) parseLocalAliases(ctx context.Context, entityID string) (*identity.LocalAliases, error) {
	var localAliases *identity.LocalAliases
	view := i.localAliasPacker(ctx).View()

	if err := logical.WithTransaction(ctx, view, func(s logical.Storage) error {
		item, err := i.localAliasPacker(ctx).GetItemWithStorage(s, entityID)
		if err != nil {
			return err
		}
		if item == nil {
			return nil
		}

		localAliases = new(identity.LocalAliases)
		err = item.Message.UnmarshalTo(localAliases)
		if err != nil {
			return err
		}

		persistNeeded := false
		for _, alias := range localAliases.Aliases {
			if alias.NamespaceID == "" {
				alias.NamespaceID = namespace.RootNamespaceID
			}

			if alias.ID != "" && alias.NamespaceID != "" && alias.NamespaceID != namespace.RootNamespaceID && !strings.HasSuffix(alias.ID, alias.NamespaceID) {
				alias.ID = fmt.Sprintf("%v.%v", alias.ID, alias.NamespaceID)
				persistNeeded = true
			}
		}

		if persistNeeded {
			aliasesAsAny, err := anypb.New(localAliases)
			if err != nil {
				return err
			}

			item.Message = aliasesAsAny

			err = i.localAliasPacker(ctx).PutItemWithStorage(ctx, s, item)
			if err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return localAliases, nil
}

func (i *IdentityStore) parseEntityFromBucketItem(ctx context.Context, item *storagepacker.Item) (*identity.Entity, error) {
	if item == nil {
		return nil, errors.New("nil item")
	}

	persistNeeded := false

	var entity identity.Entity
	err := item.Message.UnmarshalTo(&entity)
	if err != nil {
		// If we encounter an error, it would mean that the format of the
		// entity is an older one. Try decoding using the older format and if
		// successful, upgrage the storage with the newer format.
		var oldEntity identity.EntityStorageEntry
		oldEntityErr := item.Message.UnmarshalTo(&oldEntity)
		if oldEntityErr != nil {
			return nil, fmt.Errorf("failed to decode entity from storage bucket item: %w", err)
		}

		i.logger.Debug("upgrading the entity using patch introduced with vault 0.8.2.1", "entity_id", oldEntity.ID)

		// Successfully decoded entity using older format. Entity is stored
		// with older format. Upgrade it.
		entity.ID = oldEntity.ID
		entity.Name = oldEntity.Name
		entity.Metadata = oldEntity.Metadata
		entity.CreationTime = oldEntity.CreationTime
		entity.LastUpdateTime = oldEntity.LastUpdateTime
		entity.MergedEntityIDs = oldEntity.MergedEntityIDs
		entity.Policies = oldEntity.Policies
		entity.BucketKey = oldEntity.BucketKeyHash
		entity.MFASecrets = oldEntity.MFASecrets
		// Copy each alias individually since the format of aliases were
		// also different
		for _, oldAlias := range oldEntity.Personas {
			var newAlias identity.Alias
			newAlias.ID = oldAlias.ID
			newAlias.Name = oldAlias.Name
			newAlias.CanonicalID = oldAlias.EntityID
			newAlias.MountType = oldAlias.MountType
			newAlias.MountAccessor = oldAlias.MountAccessor
			newAlias.MountPath = oldAlias.MountPath
			newAlias.Metadata = oldAlias.Metadata
			newAlias.CreationTime = oldAlias.CreationTime
			newAlias.LastUpdateTime = oldAlias.LastUpdateTime
			newAlias.MergedFromCanonicalIDs = oldAlias.MergedFromEntityIDs
			entity.UpsertAlias(&newAlias)
		}

		persistNeeded = true
	}

	pN, err := parseExtraEntityFromBucket(ctx, i, &entity)
	if err != nil {
		return nil, err
	}
	if pN {
		persistNeeded = true
	}

	if entity.NamespaceID == "" {
		entity.NamespaceID = namespace.RootNamespaceID
	}

	oldId := entity.ID
	if entity.ID != "" && entity.NamespaceID != "" && entity.NamespaceID != namespace.RootNamespaceID && !strings.HasSuffix(entity.ID, entity.NamespaceID) {
		entity.ID = fmt.Sprintf("%v.%v", entity.ID, entity.NamespaceID)
		persistNeeded = true
	}

	if persistNeeded {
		entityAsAny, err := anypb.New(&entity)
		if err != nil {
			return nil, err
		}

		item := &storagepacker.Item{
			ID:      entity.ID,
			Message: entityAsAny,
		}

		// Store the entity with new format
		if oldId == entity.ID {
			err = i.entityPacker(ctx).PutItem(ctx, item)
			if err != nil {
				return nil, err
			}
		} else {
			// We may have modified formats, but we likely just changed
			// identifier. Make sure we update all aliases as well! We leave
			// the updating of the actual aliases' identifiers to
			// parseLocalAliases(...).
			err = i.entityPacker(ctx).SwapItem(ctx, oldId, item)
			if err != nil {
				return nil, err
			}

			aliasItem, err := i.localAliasPacker(ctx).GetItem(oldId)
			if err != nil {
				return nil, err
			}
			if aliasItem != nil {
				aliasItem.ID = item.ID
				err = i.localAliasPacker(ctx).SwapItem(ctx, oldId, aliasItem)
				if err != nil {
					return nil, fmt.Errorf("error moving entity alias: %w", err)
				}
			}
		}
	}

	return &entity, nil
}

func (i *IdentityStore) parseCachedEntity(item *storagepacker.Item) (*identity.Entity, error) {
	if item == nil {
		return nil, errors.New("nil item")
	}

	var entity identity.Entity
	err := item.Message.UnmarshalTo(&entity)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cached entity from storage bucket item: %w", err)
	}

	if entity.NamespaceID == "" {
		entity.NamespaceID = namespace.RootNamespaceID
	}

	return &entity, nil
}

func (i *IdentityStore) parseGroupFromBucketItem(ctx context.Context, item *storagepacker.Item) (*identity.Group, error) {
	if item == nil {
		return nil, errors.New("nil item")
	}

	var group identity.Group
	err := item.Message.UnmarshalTo(&group)
	if err != nil {
		return nil, fmt.Errorf("failed to decode group from storage bucket item: %w", err)
	}

	if group.NamespaceID == "" {
		group.NamespaceID = namespace.RootNamespaceID
	}

	persistNeeded := false
	oldId := group.ID
	if group.ID != "" && group.NamespaceID != "" && group.NamespaceID != namespace.RootNamespaceID && !strings.HasSuffix(group.ID, group.NamespaceID) {
		group.ID = fmt.Sprintf("%v.%v", group.ID, group.NamespaceID)
		persistNeeded = true
	}

	if persistNeeded {
		groupAsAny, err := anypb.New(&group)
		if err != nil {
			return nil, err
		}

		item := &storagepacker.Item{
			ID:      group.ID,
			Message: groupAsAny,
		}

		if oldId == group.ID {
			err = i.groupPacker(ctx).PutItem(ctx, item)
		} else {
			err = i.groupPacker(ctx).SwapItem(ctx, oldId, item)
		}
		if err != nil {
			return nil, err
		}
	}

	return &group, nil
}

// entityByAliasFactors fetches the entity based on factors of alias, i.e mount
// accessor and the alias name, using the given context.
// This function respects namespace boundaries and will only return an entity that belongs to the
// same namespace as the context.
func (i *IdentityStore) entityByAliasFactors(ctx context.Context, mountAccessor, aliasName string, clone bool) (*identity.Entity, error) {
	if mountAccessor == "" {
		return nil, errors.New("missing mount accessor")
	}

	if aliasName == "" {
		return nil, errors.New("missing alias name")
	}

	if err := i.validateCtx(ctx); err != nil {
		return nil, err
	}

	txn := i.db(ctx).Txn(false)

	return i.entityByAliasFactorsInTxn(ctx, txn, mountAccessor, aliasName, clone)
}

// entityByAliasFactorsInTxn fetches the entity based on factors of alias, i.e
// mount accessor and the alias name.
func (i *IdentityStore) entityByAliasFactorsInTxn(ctx context.Context, txn *memdb.Txn, mountAccessor, aliasName string, clone bool) (*identity.Entity, error) {
	if txn == nil {
		return nil, errors.New("nil txn")
	}

	if mountAccessor == "" {
		return nil, errors.New("missing mount accessor")
	}

	if aliasName == "" {
		return nil, errors.New("missing alias name")
	}

	alias, err := i.MemDBAliasByFactorsInTxn(txn, mountAccessor, aliasName, false, false)
	if err != nil {
		return nil, err
	}

	if alias == nil {
		return nil, nil
	}

	return i.MemDBEntityByAliasIDInTxn(txn, alias.ID, clone)
}

// CreateOrFetchEntity creates a new entity or returns an existing entity based on the alias,
// respecting namespace boundaries defined by the context.
// Entities and aliases are always created in the namespace from which the request originated (derived from ctx).
func (i *IdentityStore) CreateOrFetchEntity(ctx context.Context, alias *logical.Alias) (*identity.Entity, bool, error) {
	defer metrics.MeasureSince([]string{"identity", "create_or_fetch_entity"}, time.Now())

	var entity *identity.Entity
	var err error
	var update bool
	var entityCreated bool

	if alias == nil {
		return nil, false, errors.New("alias is nil")
	}

	if alias.Name == "" {
		return nil, false, errors.New("empty alias name")
	}

	mountValidationResp := i.router.ValidateMountByAccessor(alias.MountAccessor)
	if mountValidationResp == nil {
		return nil, false, fmt.Errorf("invalid mount accessor %q", alias.MountAccessor)
	}

	if mountValidationResp.MountType != alias.MountType {
		return nil, false, fmt.Errorf("mount accessor %q is not a mount of type %q", alias.MountAccessor, alias.MountType)
	}

	// Get namespace from the context
	ns, nsErr := namespace.FromContext(ctx)
	if nsErr != nil {
		return nil, false, nsErr
	}

	// Check if an entity already exists for the given alias
	entity, err = i.entityByAliasFactors(ctx, alias.MountAccessor, alias.Name, true)
	if err != nil {
		return nil, false, err
	}
	// The entity lookup is already namespace aware, but we check anyway for clarity
	if entity != nil && changedAliasIndex(entity, alias) == -1 {
		return entity, false, nil
	}

	i.lock.Lock()
	defer i.lock.Unlock()

	// Create a MemDB transaction to update both alias and entity
	txn := i.db(ctx).Txn(true)
	defer txn.Abort()

	// Check if an entity was created before acquiring the lock
	entity, err = i.entityByAliasFactorsInTxn(ctx, txn, alias.MountAccessor, alias.Name, true)
	if err != nil {
		return nil, false, err
	}
	// The entity lookup is already namespace aware, but we check anyway for clarity
	if entity != nil {
		idx := changedAliasIndex(entity, alias)
		if idx == -1 {
			return entity, false, nil
		}
		a := entity.Aliases[idx]
		a.Metadata = alias.Metadata
		a.LastUpdateTime = timestamppb.Now()

		update = true
	}

	if !update {
		entity = new(identity.Entity)

		// Set namespace ID from context
		entity.NamespaceID = ns.ID

		err = i.sanitizeEntity(ctx, entity)
		if err != nil {
			return nil, false, err
		}

		// Create a new alias
		newAlias := &identity.Alias{
			CanonicalID:   entity.ID,
			Name:          alias.Name,
			MountAccessor: alias.MountAccessor,
			Metadata:      alias.Metadata,
			MountPath:     mountValidationResp.MountPath,
			MountType:     mountValidationResp.MountType,
			Local:         alias.Local,
			NamespaceID:   entity.NamespaceID, // Ensure alias has same namespace as entity
		}

		err = i.sanitizeAlias(ctx, newAlias)
		if err != nil {
			return nil, false, err
		}

		i.logger.Debug("creating a new entity", "alias", newAlias)

		// Append the new alias to the new entity
		entity.Aliases = []*identity.Alias{
			newAlias,
		}

		i.metrics.IncrCounterWithLabels(
			[]string{"identity", "entity", "creation"},
			1,
			[]metrics.Label{
				metricsutil.NamespaceLabel(ns),
				{Name: "auth_method", Value: newAlias.MountType},
				{Name: "mount_point", Value: newAlias.MountPath},
			})
		entityCreated = true
	}

	// Update MemDB and persist entity object
	err = i.upsertEntityInTxn(ctx, txn, entity, nil, true)
	if err != nil {
		return entity, entityCreated, err
	}

	txn.Commit()
	clonedEntity, err := entity.Clone()
	return clonedEntity, entityCreated, err
}

// changedAliasIndex searches an entity for changed alias metadata.
//
// If a match is found, the changed alias's index is returned. If no alias
// names match or no metadata is different, -1 is returned.
func changedAliasIndex(entity *identity.Entity, alias *logical.Alias) int {
	for i, a := range entity.Aliases {
		if a.Name == alias.Name && a.MountAccessor == alias.MountAccessor && !strutil.EqualStringMaps(a.Metadata, alias.Metadata) {
			return i
		}
	}

	return -1
}
