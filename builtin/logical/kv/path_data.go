package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pathConfig returns the path configuration for CRUD operations on the backend
// configuration.
func pathData(b *versionedKVBackend) *framework.Path {
	return &framework.Path{
		Pattern: "data/" + framework.MatchAllRegex("path"),
		Fields: map[string]*framework.FieldSchema{
			"path": {
				Type:        framework.TypeString,
				Description: "Location of the secret.",
			},
			"version": {
				Type:        framework.TypeInt,
				Description: "If provided during a read, the value at the version number will be returned",
			},
			"options": {
				Type: framework.TypeMap,
				Description: `Options for writing a KV entry.

Set the "cas" value to use a Check-And-Set operation. If not set the write will
be allowed. If set to 0 a write will only be allowed if the key doesn’t exist.
If the index is non-zero the write will only be allowed if the key’s current
version matches the version specified in the cas parameter.`,
			},
			"data": {
				Type:        framework.TypeMap,
				Description: "The contents of the data map will be stored and returned on read.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.upgradeCheck(b.pathDataWrite()),
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.upgradeCheck(b.pathDataWrite()),
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.upgradeCheck(b.pathDataRead()),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.upgradeCheck(b.pathDataDelete()),
			},
			logical.PatchOperation: &framework.PathOperation{
				Callback: b.upgradeCheck(b.pathDataPatch()),
			},
		},

		ExistenceCheck: b.dataExistenceCheck(),

		HelpSynopsis:    dataHelpSyn,
		HelpDescription: dataHelpDesc,
	}
}

func (b *versionedKVBackend) dataExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := data.Get("path").(string)

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			// If we are returning a readonly error it means we are attempting
			// to write the policy for the first time. This means no data exists
			// yet and we can safely return false here.
			if strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return false, nil
			}

			return false, err
		}

		return meta != nil, nil
	}
}

// pathDataRead handles read commands to a kv entry
func (b *versionedKVBackend) pathDataRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Create a read-only transaction if we can. We do not need to commit
		// this as we're not writing to storage.
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginReadOnlyTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		key := data.Get("path").(string)

		lock := locksutil.LockForKey(b.locks, key)
		lock.RLock()
		defer lock.RUnlock()

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			return nil, nil
		}

		verNum := meta.CurrentVersion
		verParam := data.Get("version").(int)
		if verParam > 0 {
			verNum = uint64(verParam)
		}

		// If there is no version with that number, return
		vm := meta.Versions[verNum]
		if vm == nil {
			return nil, nil
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"data": nil,
				"metadata": map[string]interface{}{
					"version":         verNum,
					"created_time":    ptypesTimestampToString(vm.CreatedTime),
					"deletion_time":   ptypesTimestampToString(vm.DeletionTime),
					"destroyed":       vm.Destroyed,
					"custom_metadata": meta.CustomMetadata,
				},
			},
		}

		// If the version has been deleted return metadata with a 404
		if vm.DeletionTime != nil {
			if err := vm.DeletionTime.CheckValid(); err != nil {
				return nil, err
			}
			deletionTime := vm.DeletionTime.AsTime()

			if deletionTime.Before(time.Now()) {
				return logical.RespondWithStatusCode(resp, req, http.StatusNotFound)
			}
		}

		// If the version has been destroyed return metadata with a 404
		if vm.Destroyed {
			return logical.RespondWithStatusCode(resp, req, http.StatusNotFound)
		}

		versionKey, err := b.getVersionKey(ctx, key, verNum, req.Storage)
		if err != nil {
			return nil, err
		}

		raw, err := req.Storage.Get(ctx, versionKey)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("could not find version data")
		}

		version := &Version{}
		if err := proto.Unmarshal(raw.Value, version); err != nil {
			return nil, err
		}

		vData := map[string]interface{}{}
		if err := json.Unmarshal(version.Data, &vData); err != nil {
			return nil, err
		}

		resp.Data["data"] = vData

		return resp, nil
	}
}

// validateCheckAndSetOption will validate the cas flag from the options map
// provided. The cas flag must be provided if required based on the engine's
// config or the secret's key metadata. If provided, the cas value must match
// the current version of the secret as denoted by its key metadata entry.
func validateCheckAndSetOption(data *framework.FieldData, config *Configuration, meta *KeyMetadata) error {
	var casRaw interface{}
	var casOk bool
	optionsRaw, ok := data.GetOk("options")
	if ok {
		options := optionsRaw.(map[string]interface{})

		// Verify the CAS parameter is valid.
		casRaw, casOk = options["cas"]
	}

	if casOk {
		var cas int
		if err := mapstructure.WeakDecode(casRaw, &cas); err != nil {
			return errors.New("error parsing check-and-set parameter")
		}
		if uint64(cas) != meta.CurrentVersion {
			return errors.New("check-and-set parameter did not match the current version")
		}
	} else if config.CasRequired || meta.CasRequired {
		return errors.New("check-and-set parameter required for this call")
	}

	return nil
}

// cleanupOldVersions is responsible for cleaning up old versions. Once a key
// has more than the configured allowed versions the oldest version will be
// permanently deleted. A list of version keys to delete will be created.
// Indices will be ordered such that the oldest version is at the end of the
// list. Deletes will be performed back-to-front. If there is an error deleting
// one of the keys, the remaining keys will be deleted on the next go around.
func (b *versionedKVBackend) cleanupOldVersions(ctx context.Context, storage logical.Storage, key string, versionToDelete uint64) string {
	warningFormat := "error occurred when cleaning up old versions, these will be cleaned up on next write: %s"

	var versionKeysToDelete []string

	for i := versionToDelete; i > 0; i-- {
		versionKey, err := b.getVersionKey(ctx, key, i, storage)
		if err != nil {
			return fmt.Sprintf(warningFormat, err)
		}

		v, err := storage.Get(ctx, versionKey)
		if err != nil {
			return fmt.Sprintf(warningFormat, err)
		}

		if v == nil {
			break
		}

		// append to the end of the list
		versionKeysToDelete = append(versionKeysToDelete, versionKey)
	}

	// Walk the list backwards deleting the oldest versions first. This
	// allows us to continue the cleanup on next write if an error
	// occurs during one of the deletes.
	for i := len(versionKeysToDelete) - 1; i >= 0; i-- {
		err := storage.Delete(ctx, versionKeysToDelete[i])
		if err != nil {
			return fmt.Sprintf(warningFormat, err)
		}
	}

	return ""
}

// pathDataWrite handles create and update commands to a kv entry
func (b *versionedKVBackend) pathDataWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)
		if key == "" {
			return logical.ErrorResponse("missing path"), nil
		}

		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		// Parse data, this can happen before the lock so we can fail early if
		// not set.
		var marshaledData []byte
		{
			dataRaw, ok := data.GetOk("data")
			if !ok {
				return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
			}
			marshaledData, err = json.Marshal(dataRaw.(map[string]interface{}))
			if err != nil {
				return nil, err
			}
		}

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			meta = &KeyMetadata{
				Key:      key,
				Versions: map[uint64]*VersionMetadata{},
			}
		}

		err = validateCheckAndSetOption(data, config, meta)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}

		// Create a version key for the new version
		versionKey, err := b.getVersionKey(ctx, key, meta.CurrentVersion+1, req.Storage)
		if err != nil {
			return nil, err
		}
		version := &Version{
			Data:        marshaledData,
			CreatedTime: timestamppb.Now(),
		}

		ctime := version.CreatedTime.AsTime()

		if !config.IsDeleteVersionAfterDisabled() {
			if dtime, ok := deletionTime(ctime, deleteVersionAfter(config), deleteVersionAfter(meta)); ok {
				version.DeletionTime = timestamppb.New(dtime)
				if err := version.DeletionTime.CheckValid(); err != nil {
					return logical.ErrorResponse("error setting deletion_time: converting %v to protobuf: %v", dtime, err), logical.ErrInvalidRequest
				}
			}
		}

		buf, err := proto.Marshal(version)
		if err != nil {
			return nil, err
		}

		// Write the new version
		if err := req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   versionKey,
			Value: buf,
		}); err != nil {
			return nil, err
		}

		// Add version to the key metadata and calculate version to delete
		// based on the max_versions specified by either the secret's key
		// metadata or the engine's config
		vm, versionToDelete := meta.AddVersion(version.CreatedTime, version.DeletionTime, config.MaxVersions)

		err = b.writeKeyMetadata(ctx, req.Storage, meta)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"version":         meta.CurrentVersion,
				"created_time":    ptypesTimestampToString(vm.CreatedTime),
				"deletion_time":   ptypesTimestampToString(vm.DeletionTime),
				"destroyed":       vm.Destroyed,
				"custom_metadata": meta.CustomMetadata,
			},
		}

		warning := b.cleanupOldVersions(ctx, req.Storage, key, versionToDelete)
		if warning != "" {
			// A failed attempt to clean up old versions will be retried on
			// next write attempt, prefer a warning over an error resp
			resp.AddWarning(warning)
		}

		// Commit our transaction if we created one! We're done making
		// modifications to storage.
		if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
			if err := txn.Commit(ctx); err != nil {
				return nil, err
			}
			req.Storage = originalStorage
		}

		return resp, nil
	}
}

// patchPreprocessor is passed to framework.HandlePatchOperation within the
// pathDataPatch handler. The framework.HandlePatchOperation abstraction
// expects only the resource data to be provided. The "data" key must be lifted
// from the request data to the pathDataPatch handler since it also accepts an
// options map.
func dataPatchPreprocessor() framework.PatchPreprocessorFunc {
	return func(input map[string]interface{}) (map[string]interface{}, error) {
		data, ok := input["data"]

		if !ok {
			return nil, errors.New("no data provided")
		}

		return data.(map[string]interface{}), nil
	}
}

// pathDataPatch handles the patch command to a kv entry. A PatchOperation must
// be performed on an existing entry specified by the provided path. This
// handler supports the "cas" flag and is required if cas_required is set to true
// on either the secret or the engine's config. In order for a patch to be
// successful, cas must be set to the current version of the secret. The contents
// of the data map under the "data" key will be applied as a partial update to
// the existing entry via a JSON merge patch to the existing entry using the
// framework.HandlePatchOperation abstraction.
func (b *versionedKVBackend) pathDataPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)

		// Only validate that data is present to provide error response since
		// HandlePatchOperation and dataPatchPreprocessor will ultimately
		// properly parse the field
		_, ok := data.GetOk("data")
		if !ok {
			return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
		}

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}

		if meta == nil {
			return logical.RespondWithStatusCode(nil, req, http.StatusNotFound)
		}

		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		err = validateCheckAndSetOption(data, config, meta)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}

		currentVersion := meta.CurrentVersion

		versionMetadata := meta.Versions[currentVersion]

		if versionMetadata == nil {
			return logical.RespondWithStatusCode(nil, req, http.StatusNotFound)
		}

		// Like the read handler, initialize a resp with the version metadata
		// to be used in a 404 response when the entry has either been deleted
		// or destroyed
		notFoundResp := &logical.Response{
			Data: map[string]interface{}{
				"version":         currentVersion,
				"created_time":    ptypesTimestampToString(versionMetadata.CreatedTime),
				"deletion_time":   ptypesTimestampToString(versionMetadata.DeletionTime),
				"destroyed":       versionMetadata.Destroyed,
				"custom_metadata": meta.CustomMetadata,
			},
		}

		if versionMetadata.DeletionTime != nil {
			if err := versionMetadata.DeletionTime.CheckValid(); err != nil {
				return nil, err
			}
			deletionTime := versionMetadata.DeletionTime.AsTime()

			if deletionTime.Before(time.Now()) {
				return logical.RespondWithStatusCode(notFoundResp, req, http.StatusNotFound)
			}
		}

		if versionMetadata.Destroyed {
			return logical.RespondWithStatusCode(notFoundResp, req, http.StatusNotFound)
		}

		currentVersionKey, err := b.getVersionKey(ctx, key, currentVersion, req.Storage)
		if err != nil {
			return nil, err
		}

		raw, err := req.Storage.Get(ctx, currentVersionKey)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("could not find version data")
		}

		existingVersion := &Version{}

		if err := proto.Unmarshal(raw.Value, existingVersion); err != nil {
			return nil, err
		}

		var versionData map[string]interface{}
		if err := json.Unmarshal(existingVersion.Data, &versionData); err != nil {
			return nil, err
		}

		patchedBytes, err := framework.HandlePatchOperation(data, versionData, dataPatchPreprocessor())
		if err != nil {
			return nil, err
		}

		newVersion := &Version{
			Data:        patchedBytes,
			CreatedTime: timestamppb.Now(),
		}

		ctime := newVersion.CreatedTime.AsTime()

		// Set the deletion_time for the new version based on delete_version_after value if set
		// on either the secret's key metadata or the engine's config
		if !config.IsDeleteVersionAfterDisabled() {
			if dtime, ok := deletionTime(ctime, deleteVersionAfter(config), deleteVersionAfter(meta)); ok {
				newVersion.DeletionTime = timestamppb.New(dtime)
				if err := newVersion.DeletionTime.CheckValid(); err != nil {
					return logical.ErrorResponse("error setting deletion_time: converting %v to protobuf: %v", dtime, err), logical.ErrInvalidRequest
				}
			}
		}

		buf, err := proto.Marshal(newVersion)
		if err != nil {
			return nil, err
		}

		newVersionKey, err := b.getVersionKey(ctx, key, meta.CurrentVersion+1, req.Storage)
		if err != nil {
			return nil, err
		}

		if err := req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   newVersionKey,
			Value: buf,
		}); err != nil {
			return nil, err
		}

		// Add version to the key metadata and calculate version to delete
		// based on the max_versions specified by either the secret's key
		// metadata or the engine's config
		newVersionMetadata, versionToDelete := meta.AddVersion(newVersion.CreatedTime, newVersion.DeletionTime, config.MaxVersions)

		err = b.writeKeyMetadata(ctx, req.Storage, meta)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"version":         meta.CurrentVersion,
				"created_time":    ptypesTimestampToString(newVersionMetadata.CreatedTime),
				"deletion_time":   ptypesTimestampToString(newVersionMetadata.DeletionTime),
				"destroyed":       newVersionMetadata.Destroyed,
				"custom_metadata": meta.CustomMetadata,
			},
		}

		warning := b.cleanupOldVersions(ctx, req.Storage, key, versionToDelete)
		if warning != "" {
			// A failed attempt to clean up old versions will be retried on
			// next patch attempt, prefer a warning over an error resp
			resp.AddWarning(warning)
		}

		// Commit our transaction if we created one! We're done making
		// modifications to storage.
		if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
			if err := txn.Commit(ctx); err != nil {
				return nil, err
			}
			req.Storage = originalStorage
		}

		return resp, nil
	}
}

func (b *versionedKVBackend) pathDataDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			return nil, nil
		}

		// If there is no latest version, or the latest version is already
		// deleted or destroyed return
		lv := meta.Versions[meta.CurrentVersion]
		if lv == nil || lv.Destroyed {
			return nil, nil
		}

		if lv.DeletionTime != nil {
			if err := lv.DeletionTime.CheckValid(); err != nil {
				return nil, err
			}
			deletionTime := lv.DeletionTime.AsTime()

			if deletionTime.Before(time.Now()) {
				return nil, nil
			}
		}

		lv.DeletionTime = timestamppb.Now()

		err = b.writeKeyMetadata(ctx, req.Storage, meta)
		if err != nil {
			return nil, err
		}

		// Commit our transaction if we created one! We're done making
		// modifications to storage.
		if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
			if err := txn.Commit(ctx); err != nil {
				return nil, err
			}
			req.Storage = originalStorage
		}

		return nil, nil
	}
}

// AddVersion adds a version to the key metadata and moves the sliding window of
// max versions. It returns the newly added version and the version to delete
// from storage.
func (k *KeyMetadata) AddVersion(createdTime, deletionTime *timestamppb.Timestamp, configMaxVersions uint32) (*VersionMetadata, uint64) {
	if k.Versions == nil {
		k.Versions = map[uint64]*VersionMetadata{}
	}

	vm := &VersionMetadata{
		CreatedTime:  createdTime,
		DeletionTime: deletionTime,
	}

	k.CurrentVersion++
	k.Versions[k.CurrentVersion] = vm
	k.UpdatedTime = createdTime
	if k.CreatedTime == nil {
		k.CreatedTime = createdTime
	}

	var maxVersions uint32
	switch {
	case max(k.MaxVersions, configMaxVersions) > 0:
		maxVersions = max(k.MaxVersions, configMaxVersions)
	default:
		maxVersions = defaultMaxVersions
	}

	if uint32(k.CurrentVersion-k.OldestVersion) >= maxVersions {
		versionToDelete := k.CurrentVersion - uint64(maxVersions)
		// We need to do a loop here in the event that max versions has
		// changed and we need to delete more than one entry.
		for i := k.OldestVersion; i < versionToDelete+1; i++ {
			delete(k.Versions, i)
		}

		k.OldestVersion = versionToDelete + 1

		return vm, versionToDelete
	}

	return vm, 0
}

func max(a, b uint32) uint32 {
	if b > a {
		return b
	}

	return a
}

const (
	dataHelpSyn  = `Write, Patch, Read, and Delete data in the Key-Value Store.`
	dataHelpDesc = `
This path takes a key name and based on the operation stores, retrieves or
deletes versions of data.

If a write operation is used the endpoint takes an options object and a data
object. The options object is used to pass some options to the write command and
the data object is encrypted and stored in the storage backend. Each write
operation for a key creates a new version and does not overwrite the previous
data.

A patch operation must be performed on an existing secret. The secret must neither
be deleted nor destroyed. Like a write operation, patch operations accept an
options object and data object. The options object is used to pass some options to
the patch command and the data object is used to perform a partial update on the
current version of the secret and store the encrypted result in the storage backend.

A read operation will return the latest version for a key unless the "version"
parameter is set, then it returns the version at that number.

Delete operations are a soft delete. They will mark the latest version as
deleted, but the underlying data will not be fully removed. Delete operations
can be undone.
`
)
