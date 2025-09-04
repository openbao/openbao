// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"regexp"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-memdb"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/storagepacker"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// metaKeyFormatRegEx checks if a metadata key string is valid
var metaKeyFormatRegEx = regexp.MustCompile(`^[a-zA-Z0-9=/+_-]+$`).MatchString

const (
	// The meta key prefix reserved for Vault's internal use
	metaKeyReservedPrefix = "vault-"

	// The maximum number of metadata key pairs allowed to be registered
	metaMaxKeyPairs = 64

	// The maximum allowed length of a metadata key
	metaKeyMaxLength = 128

	// The maximum allowed length of a metadata value
	metaValueMaxLength = 512
)

type identityStoreNamespaceView struct {
	// view is the storage sub-view where all the artifacts of identity store
	// gets persisted
	view logical.Storage

	// entityPacker is used to pack multiple entity storage entries into 256
	// buckets
	entityPacker *storagepacker.StoragePacker

	// localAliasPacker is used to pack multiple local alias entries into lesser
	// storage entries. This is also used to cache entities in the secondary
	// clusters, those entities which were created by the primary but hasn't
	// reached secondary via invalidations.
	localAliasPacker *storagepacker.StoragePacker

	// groupPacker is used to pack multiple group storage entries into 256
	// buckets
	groupPacker *storagepacker.StoragePacker

	// db is the in-memory database where the storage artifacts gets replicated
	// to enable richer queries based on multiple indexes.
	db *memdb.MemDB
}

// IdentityStore is composed of its own storage view and a MemDB which
// maintains active in-memory replicas of the storage contents indexed by
// multiple fields.
type IdentityStore struct {
	// IdentityStore is a secret backend in Vault
	*framework.Backend

	// views is a mapping of namespace UUID -> storage view and packer
	// instances.
	views sync.Map

	// locks to make sure things are consistent
	lock     sync.RWMutex
	oidcLock sync.RWMutex

	// groupLock is used to protect modifications to group entries
	groupLock sync.RWMutex

	// oidcCache stores common response data as well as when the periodic func needs
	// to run. This is conservatively managed, and most writes to the OIDC endpoints
	// will invalidate the cache.
	oidcCache *oidcCache

	// oidcAuthCodeCache stores OIDC authorization codes to be exchanged
	// for an ID token during an authorization code flow.
	oidcAuthCodeCache *oidcCache

	// logger is the server logger copied over from core
	logger log.Logger

	// disableLowerCaseNames indicates whether or not identity artifacts are
	// operated case insensitively
	disableLowerCasedNames bool

	router        *Router
	redirectAddr  string
	localNode     LocalNode
	namespacer    Namespacer
	metrics       metricsutil.Metrics
	totpPersister TOTPPersister
	tokenStorer   TokenStorer
	mfaBackend    *LoginMFABackend
}

type groupDiff struct {
	New        []*identity.Group
	Deleted    []*identity.Group
	Unmodified []*identity.Group
}

type casesensitivity struct {
	DisableLowerCasedNames bool `json:"disable_lower_cased_names"`
}

type LocalNode interface {
	ReplicationState() consts.ReplicationState
	HAState() consts.HAState
}

var _ LocalNode = &Core{}

type Namespacer interface {
	NamespaceByID(context.Context, string) (*namespace.Namespace, error)
	ListNamespaces(context.Context) ([]*namespace.Namespace, error)
}

var _ Namespacer = &Core{}

type TOTPPersister interface {
	PersistTOTPKey(ctx context.Context, configID string, entityID string, key string) error
}

var _ TOTPPersister = &Core{}

type TokenStorer interface {
	LookupToken(context.Context, string) (*logical.TokenEntry, error)
	CreateToken(context.Context, *logical.TokenEntry, bool) error
}

var _ TokenStorer = &Core{}
