package ssh

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestMigrateStorage_EmptyStorage(t *testing.T) {
	t.Parallel()
	startTime := time.Now()
	ctx := context.Background()
	b, s := CreateBackendWithStorage(t)
	sc := b.makeStorageContext(ctx, s)

	// Fetch migration log
	log, err := getMigrationLog(ctx, s)
	require.NoError(t, err)
	require.Nil(t, log)

	request := &logical.InitializationRequest{Storage: s}
	err = b.initialize(ctx, request)
	require.NoError(t, err)

	// Fetch migration log again
	log, err = getMigrationLog(ctx, s)
	require.NotNil(t, log)
	require.Equal(t, latestMigrationVersion, log.MigrationVersion)
	require.True(t, startTime.Before(log.Created),
		"created migration info entry time (%v) was before our start time(%v)?", log.Created, startTime)

	// Validate that there are no issuers configured before
	issuerIds, err := sc.listIssuers()
	require.NoError(t, err)
	require.Equal(t, 0, len(issuerIds))
}

func TestMigrateStorage_CAConfigured(t *testing.T) {
	t.Parallel()
	startTime := time.Now()
	ctx := context.Background()
	b, s := CreateBackendWithStorage(t)
	sc := b.makeStorageContext(ctx, s)

	// Fetch migration log that should not exist
	log, err := getMigrationLog(ctx, s)
	require.Nil(t, log)
	require.NoError(t, err)

	// Configure CA key material
	// Set CA public key
	json, err := logical.StorageEntryJSON(caPublicKeyStoragePath, &keyStorageEntry{
		Key: testCAPublicKey,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Set CA private key
	json, err = logical.StorageEntryJSON(caPrivateKeyStoragePath, &keyStorageEntry{
		Key: testCAPrivateKey,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Validate that there were no issuers, in the new path, configured before
	// the migration
	issuerIds, err := sc.listIssuers()
	require.NoError(t, err)
	require.Empty(t, issuerIds)

	request := &logical.InitializationRequest{Storage: s}
	err = b.initialize(ctx, request)
	require.NoError(t, err)

	// Fetch migration log again
	log, err = getMigrationLog(ctx, s)
	require.NotNil(t, log)
	require.NoError(t, err)
	require.Equal(t, latestMigrationVersion, log.MigrationVersion)
	require.True(t, startTime.Before(log.Created),
		"created migration info entry time (%v) was before our start time(%v)?", log.Created, startTime)

	// Verify that issuer has been set as default
	entry, err := sc.fetchDefaultIssuer()
	require.NotNil(t, entry)
	require.NoError(t, err)
	require.Equal(t, log.CreatedIssuer, entry.ID)

	// Make sure if we attempt to re-run the migration nothing happens...
	err = migrateStorage(ctx, b, s)
	require.NoError(t, err)

	// Fetch the migration log again and compare with what we had before
	// as the key material did not change, the migration should not have been executed
	newLog, err := getMigrationLog(ctx, s)
	require.NotNil(t, newLog)
	require.NoError(t, err)
	require.Equal(t, log, newLog)

	// Update key material in CA and run storage migration again,
	// as the key material is different a new migration should run
	startTime = time.Now()

	// Set CA public key
	json, err = logical.StorageEntryJSON(caPublicKeyStoragePath, &keyStorageEntry{
		Key: testCAPublicKeyEd25519,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Set CA private key
	json, err = logical.StorageEntryJSON(caPrivateKeyStoragePath, &keyStorageEntry{
		Key: testCAPrivateKeyEd25519,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Initialize
	err = b.initialize(ctx, request)
	require.NoError(t, err)

	// Fetch migration log
	log, err = getMigrationLog(ctx, s)
	require.NotNil(t, log)
	require.NoError(t, err)
	require.Equal(t, latestMigrationVersion, log.MigrationVersion)
	require.True(t, startTime.Before(log.Created),
		"created migration info entry time (%v) was before our start time(%v)?", log.Created, startTime)

	// Verify that issuer has been set as default
	entry, err = sc.fetchDefaultIssuer()
	require.NotNil(t, entry)
	require.NoError(t, err)
	require.Equal(t, log.CreatedIssuer, entry.ID)
}
