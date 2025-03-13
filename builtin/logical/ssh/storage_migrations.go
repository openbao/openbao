package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// This allows us to record the version of the migration code within the log entry
const (
	latestMigrationVersion = 1
)

type migrationInfo struct {
	isRequired        bool
	caPublicKey       string
	caPrivateKey      string
	caKeyMaterialHash string
	log               *migrationLog
}

type migrationLog struct {
	Hash             string    `json:"hash"`
	Created          time.Time `json:"created"`
	CreatedIssuer    string    `json:"issuer_id"`
	MigrationVersion int       `json:"migrationVersion"`
}

func getMigrationInfo(ctx context.Context, s logical.Storage) (migrationInfo, error) {
	var info migrationInfo
	var err error
	info.log, err = getMigrationLog(ctx, s)
	if err != nil {
		return info, err
	}

	info.caPublicKey, info.caPrivateKey, err = fetchCAKeyMaterial(ctx, s)
	if err != nil {
		return info, err
	}

	info.caKeyMaterialHash, err = computeKeyMaterialHash(info.caPublicKey, info.caPrivateKey)
	if err != nil {
		return info, err
	}

	// Migration of the key material has to run when:
	// - A migration log entry is not present, meaning that the migration has not been run
	// - A migration log entry is present but the hash of the key material does not match the hash stored in the ca's path
	if info.log == nil || info.log != nil && info.log.Hash != info.caKeyMaterialHash {
		info.isRequired = true
	}

	return info, nil
}

func migrateStorage(ctx context.Context, b *backend, s logical.Storage) error {
	info, err := getMigrationInfo(ctx, s)
	if err != nil {
		return err
	}

	if !info.isRequired {
		// No migration was deemed to be required.
		return nil
	}

	b.Logger().Info("Performing SSH migration to new issuers layout")

	caConfigured := info.caPublicKey != "" && info.caPrivateKey != ""
	var issuerId string
	if caConfigured {
		sc := b.makeStorageContext(ctx, s)
		var err error
		issuer, _, err := sc.ImportIssuer(info.caPublicKey, info.caPrivateKey, false, "", true)
		if err != nil {
			return err
		}
		b.Logger().Info("Migration generated the following id and set it as default", "issuer id", issuer.ID)
		issuerId = issuer.ID
	}

	err = setMigrationLog(ctx, s, &migrationLog{
		Hash:             info.caKeyMaterialHash,
		Created:          time.Now(),
		CreatedIssuer:    issuerId,
		MigrationVersion: latestMigrationVersion,
	})
	if err != nil {
		return err
	}

	b.Logger().Info(fmt.Sprintf("Succeeded in migrating to issuer storage version %v", latestMigrationVersion))

	return nil
}

func getMigrationLog(ctx context.Context, s logical.Storage) (*migrationLog, error) {
	entry, err := s.Get(ctx, migrationLogKey)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	log := &migrationLog{}
	err = entry.DecodeJSON(log)
	if err != nil {
		return nil, nil
	}

	return log, nil
}

func setMigrationLog(ctx context.Context, s logical.Storage, log *migrationLog) error {
	json, err := logical.StorageEntryJSON(migrationLogKey, log)
	if err != nil {
		return err
	}

	return s.Put(ctx, json)
}

func fetchCAKeyMaterial(ctx context.Context, s logical.Storage) (publicKey string, privateKey string, err error) {
	publicKeyCaEntry, err := caKey(ctx, s, caPublicKey)
	if err != nil {
		return
	}

	if publicKeyCaEntry != nil {
		publicKey = publicKeyCaEntry.Key
	}

	privateKeyCaEntry, err := caKey(ctx, s, caPublicKey)
	if err != nil {
		return
	}

	if privateKeyCaEntry != nil {
		privateKey = privateKeyCaEntry.Key
	}

	return
}

func computeKeyMaterialHash(publicKey string, privateKey string) (string, error) {
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(publicKey + privateKey)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
