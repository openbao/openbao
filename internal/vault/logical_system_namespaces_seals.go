// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	vaultseal "github.com/openbao/openbao/v2/internal/vault/seal"
)

func (b *SystemBackend) namespaceSealPaths() []*framework.Path {
	sealStatusSchema := map[string]*framework.FieldSchema{
		"type": {
			Type:     framework.TypeString,
			Required: true,
		},
		"initialized": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"sealed": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"t": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"n": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"progress": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
	}

	return []*framework.Path{
		{
			Pattern: "namespaces/(?P<path>.+)/seal-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationSuffix: "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Check the seal status of an OpenBao namespace.",
					Callback: b.handleNamespaceSealStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<path>.+)/seal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Seal a namespace.",
					Callback: b.handleNamespacesSeal(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					ForwardPerformanceStandby: true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)/unseal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "unseal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single namespace unseal key share.",
				},
				"reset": {
					Type:        framework.TypeBool,
					Description: "Specifies whether to reset an unseal process progress.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Unseal a namespace.",
					Callback: b.handleNamespacesUnseal(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
					ForwardPerformanceStandby: true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)/delete-sealed",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
				"force": {
					Type:        framework.TypeBool,
					Description: "If true, recursively deletes all child namespaces of the sealed namespace.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespacesDeleteSealed(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {
							{
								Description: "OK",
								Fields: map[string]*framework.FieldSchema{
									"status": {
										Type:        framework.TypeString,
										Description: "Status of the deletion operation.",
									},
								},
							},
						},
					},
					Summary: "Delete a sealed namespace by wiping its physical storage.",
				},
			},

			HelpSynopsis:    "Delete a sealed namespace.",
			HelpDescription: "Physically deletes a sealed namespace by wiping its storage. Requires sudo privilege. Pass force=true to also delete child namespaces.",
		},

		{
			Pattern: "namespaces/(?P<path>.+)/migrate-seal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "migrate-seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
				"seal": {
					Type:        framework.TypeString,
					Description: "User provided seal config.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Migrate a namespace seal.",
					Callback: b.handleNamespacesMigrateSeal(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
					ForwardPerformanceStandby: true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},
	}
}

// handleNamespaceSealStatus handles the "/sys/namespaces/<path>/seal-status"
// endpoint to retrieve a seal status of the namespace.
func (b *SystemBackend) handleNamespaceSealStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", path)
		}

		status, err := b.Core.sealManager.SealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
				"type":        status.Type,
				"initialized": status.Initialized,
				"sealed":      status.Sealed,
				"t":           status.T,
				"n":           status.N,
				"progress":    status.Progress,
				"nonce":       status.Nonce,
			},
		}, nil
	}
}

// handleNamespacesSeal handles the "/sys/namespaces/<path>/seal" endpoint to
// seal the namespace.
func (b *SystemBackend) handleNamespacesSeal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		if err := b.Core.namespaceStore.SealNamespace(ctx, path); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesUnseal handles the "/sys/namespaces/<path>/unseal" endpoint
// to unseal the namespace.
func (b *SystemBackend) handleNamespacesUnseal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", path)
		}

		resetFlag := data.Get("reset").(bool)
		if resetFlag {
			b.Core.sealManager.ResetUnsealProcess(ns.UUID)
		} else {
			key := data.Get("key").(string)
			if key == "" {
				return nil, errors.New("provided key is empty")
			}

			var decodedKey []byte
			decodedKey, err = hex.DecodeString(key)
			if err != nil {
				decodedKey, err = base64.StdEncoding.DecodeString(key)
				if err != nil {
					return handleError(err)
				}
			}

			if _, err = b.Core.namespaceStore.UnsealNamespace(ctx, path, decodedKey); err != nil {
				invalidKeyErr := &ErrInvalidKey{}
				switch {
				case errors.As(err, &invalidKeyErr):
				case errors.Is(err, barrier.ErrBarrierInvalidKey):
				case errors.Is(err, barrier.ErrBarrierNotInit):
				case errors.Is(err, barrier.ErrBarrierSealed):
				default:
					return handleError(logical.CodedError(http.StatusInternalServerError, err.Error()))
				}
				return handleError(err)
			}
		}

		status, err := b.Core.sealManager.SealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
				"type":        status.Type,
				"initialized": status.Initialized,
				"sealed":      status.Sealed,
				"t":           status.T,
				"n":           status.N,
				"progress":    status.Progress,
				"nonce":       status.Nonce,
			},
		}, nil
	}
}

// handleNamespacesDeleteSealed handles the "/sys/namespaces/<path>/delete-sealed"
// endpoint to delete a sealed namespace.
func (b *SystemBackend) handleNamespacesDeleteSealed() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		if !b.System().(extendedSystemView).SudoPrivilege(ctx, req.MountPoint+req.Path, req.ClientToken) {
			return nil, logical.ErrPermissionDenied
		}

		force := data.Get("force").(bool)
		status, err := b.Core.namespaceStore.DeleteSealedNamespace(ctx, path, force)
		if err != nil {
			return handleError(err)
		}

		if status == "" {
			resp := &logical.Response{}
			resp.AddWarning("requested namespace does not exist")
			return resp, nil
		}

		return &logical.Response{
			Data: map[string]any{"status": status},
		}, nil
	}
}

func (b *SystemBackend) handleNamespacesMigrateSeal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// TODO:
		// * create new barrier if necessary
		// * start transaction on new barrier
		// * read all relevant entries from old barrier
		// * re-write using new barrier
		// * re-write top-most namespace entry using parent barrier

		start := time.Now()

		path := namespace.Canonicalize(data.Get("path").(string))
		// unlockKey, err := b.Core.namespaceStore.LockNamespace(ctx, path)
		// if err != nil {
		// 	return handleError(err)
		// }
		// defer b.Core.namespaceStore.UnlockNamespace(ctx, unlockKey, path)

		sealRaw, ok := data.GetOk("seal")
		var sealConfig *SealConfig
		if ok {
			var err error
			sealString, ok := sealRaw.(string)
			if !ok {
				return nil, errors.New("seal config must be a HCL or JSON string")
			}
			kmses, err := configutil.ParseKMSes(sealString)
			if err != nil {
				return nil, fmt.Errorf("unable to parse seal config: %w", err)
			}
			if len(kmses) != 1 {
				return nil, errors.New("seal config must contain exactly one seal stanza")
			}
			kms := kmses[0]
			if kms.Type != "shamir" {
				return nil, errors.New("namespaces currently only support shamir seals")
			}

			sealConfig = &SealConfig{
				Type: kms.Type,
			}

			if val, ok := kms.Config["shares"]; ok {
				shares, err := parseutil.ParseInt(val)
				if err != nil {
					return nil, errors.New("value of shares parameter must be integer")
				}
				sealConfig.SecretShares = int(shares)
			}
			if val, ok := kms.Config["threshold"]; ok {
				threshold, err := parseutil.ParseInt(val)
				if err != nil {
					return nil, errors.New("value of shares parameter must be integer")
				}
				sealConfig.SecretThreshold = int(threshold)
			}
			if pgpkeys, ok := data.GetOk("pgp_keys"); ok {
				sealConfig.PGPKeys = pgpkeys.([]string)
			}

			if err := sealConfig.Validate(); err != nil {
				return logical.ErrorResponse("invalid seal config: %v", err), err
			}
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		parentNs, err := namespace.FromContext(ctx)
		if err != nil {
			return handleError(err)
		}

		if err := b.Core.namespaceStore.taintNamespace(ctx, parentNs, ns); err != nil {
			return handleError(err)
		}
		defer b.Core.namespaceStore.untaintNamespace(ctx, parentNs, ns)

		parentBarrier := b.Core.sealManager.NamespaceBarrierByLongestPrefix(parentNs.Path)
		oldBarrier := b.Core.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)

		var newBarrier barrier.SecurityBarrier
		if sealConfig == nil {
			newBarrier = parentBarrier
		}

		if newBarrier == nil {
			metaPrefix := NamespaceStoragePathPrefix(ns)
			defaultSeal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
			defaultSeal.SetCore(b.Core)
			defaultSeal.SetMetaPrefix(metaPrefix)

			defaultSeal.SetConfigAccess(parentBarrier)

			ctx := namespace.ContextWithNamespace(ctx, ns)
			if err := defaultSeal.Init(ctx); err != nil {
				return handleError(err)
			}

			newBarrier = barrier.NewAESGCMBarrier(b.Core.physical, ns)
		}

		if newBarrier == oldBarrier {
			// Nothing to do
			return nil, nil
		}

		namespacesToMigrate, err := b.Core.namespaceStore.ListNamespaces(namespace.ContextWithNamespace(ctx, ns), ListNamespaceOpts{
			IncludeSealed: false,
			Recursive:     true,
			IncludeTypes:  namespace.TypeNormal,
		})
		if err != nil {
			return handleError(err)
		}

		slices.Reverse(namespacesToMigrate)
		namespacesToMigrate = append(namespacesToMigrate, ns)

		keyInfo, err := oldBarrier.ActiveKeyInfo()
		if err != nil {
			b.logger.Warn("error getting key info of old barrier", "err", err)
		}
		b.logger.Warn("key info", "term", keyInfo.Term)

		// parentNsView := NamespaceScopedView(parentBarrier, parentNs)

		dur := time.Now().Sub(start)
		b.logger.Warn("preparation took time", "dur", dur)

		start = time.Now()

		err = logical.WithTransaction(ctx, newBarrier, func(s logical.Storage) error {
			for _, ns := range namespacesToMigrate {
				b.logger.Warn("migrating namespace", "ns", ns)
				nsPrefix := NamespaceScopedView(s, ns).Prefix()
				keys, err := recurseListKeys(ctx, oldBarrier, nsPrefix)
				if err != nil {
					return err
				}

				for _, key := range keys {
					if slices.ContainsFunc(knownNamespaceCoreEntriesToCleanup, func(k string) bool {
						return strings.HasSuffix(key, "/"+k)
					}) {
						err := s.Delete(ctx, key)
						if err != nil {
							return err
						}
						continue
					}

					b.logger.Warn("migrating", "key", key)
					pe, err := b.Core.physical.Get(ctx, key)
					if err != nil {
						b.logger.Warn("error reading key from physical storage", "key", key, "error", err)
						return err
					}
					se, err := oldBarrier.Get(ctx, key)
					if err != nil {
						b.logger.Warn("error reading key from old barrier", "key", key, "error", err, "pe", pe.Value)
						continue
					}

					err = s.Put(ctx, se)
					if err != nil {
						b.logger.Warn("error writing key to new barrier", "key", key, "error", err)
						return err
					}
					b.logger.Warn("done migrating", "key", key)
				}
			}

			switch {
			case newBarrier == parentBarrier:
				b.Core.sealManager.RemoveNamespace(ns)
			default:
				err := b.Core.sealManager.SetSeal(ctx, sealConfig, ns, SetSealOptions{
					WriteToStorage: true,
					AllowOverride:  true,
				})
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			b.logger.Warn("transaction returned error, rolling back changes")
			return handleError(err)
		}
		dur = time.Now().Sub(start)
		b.logger.Warn("transaction took time", "dur", dur)

		start = time.Now()
		var errs error
		for _, ns := range namespacesToMigrate {
			parentPath, ok := ns.ParentPath()
			if !ok {
				continue
			}
			parentNs, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, parentPath)
			if err != nil {
				errs = errors.Join(errs, err)
			}
			_, _, err = b.Core.namespaceStore.Invalidate(ctx, parentNs.UUID, ns.UUID)
			if err != nil {
				errs = errors.Join(errs, err)
			}
			//
			// errs = errors.Join(errs, b.Core.namespaceStore.pushToMounts(ns))
		}
		dur = time.Now().Sub(start)
		b.logger.Warn("invalidations took time", "dur", dur)
		if errs != nil {
			return handleError(errs)
		}

		return nil, nil
	}
}

func recurseListKeys(ctx context.Context, s logical.Storage, prefix string) ([]string, error) {
	keys, err := s.ListPage(ctx, prefix, "", -1)
	if err != nil {
		return nil, err
	}

	outKeys := make([]string, 0)

	for _, key := range keys {
		if strings.HasSuffix(key, "/") {
			recKeys, err := recurseListKeys(ctx, s, prefix+key)
			if err != nil {
				return outKeys, err
			}
			outKeys = append(outKeys, recKeys...)
			continue
		}

		outKeys = append(outKeys, prefix+key)
	}

	return outKeys, nil
}

var sysNamespacesSealsHelp = map[string][2]string{
	"namespaces-seal": {
		"Seal, unseal and delete sealable namespaces and check their seal status.",
		`
 This path responds to the following HTTP methods.
 
 	POST /<path>/seal
 		Seal a namespace.
 
 	POST /<path>/unseal
 		Unseal a namespace.
 
 	GET /<path>/seal-status
 		Returns the seal status of the namespace.
 
 	DELETE /<path>/delete-sealed
 		Delete a sealed namespace by wiping its storage.
 		`,
	},
}
