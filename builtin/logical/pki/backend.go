// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	operationPrefixPKI        = "pki"
	operationPrefixPKIIssuer  = "pki-issuer"
	operationPrefixPKIIssuers = "pki-issuers"
	operationPrefixPKIRoot    = "pki-root"

	noRole       = 0
	roleOptional = 1
	roleRequired = 2
)

/*
 * PKI requests are a bit special to keep up with the various failure and load issues.
 *
 * Any requests to write/delete shared data (such as roles, issuers, keys, and configuration)
 * are always forwarded to the Primary cluster's active node to write and send the key
 * material/config globally across all clusters. Reads should be handled locally, to give a
 * sense of where this cluster's replication state is at.
 *
 * CRL/Revocation and Fetch Certificate APIs are handled by the active node within the cluster
 * they originate. This means, if a request comes into a performance secondary cluster, the writes
 * will be forwarded to that cluster's active node and not go all the way up to the performance primary's
 * active node.
 *
 * If a certificate issue request has a role in which no_store is set to true, that node itself
 * will issue the certificate and not forward the request to the active node, as this does not
 * need to write to storage.
 *
 * To make sense of what goes where the following bits need to be analyzed within the codebase.
 *
 * 1. The backend LocalStorage paths determine what storage paths will remain within a
 *    cluster and not be forwarded to a performance primary
 * 2. Within each path's OperationHandler definition, check to see if ForwardPerformanceStandby &
 *    ForwardPerformanceSecondary flags are set to short-circuit the request to a given active node
 */

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a new Backend framework struct
func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"cert/*",
				"ca/pem",
				"ca_chain",
				"ca",
				"crl/delta",
				"crl/delta/pem",
				"crl/pem",
				"crl",
				"issuer/+/crl/der",
				"issuer/+/crl/pem",
				"issuer/+/crl",
				"issuer/+/crl/delta/der",
				"issuer/+/crl/delta/pem",
				"issuer/+/crl/delta",
				"issuer/+/pem",
				"issuer/+/der",
				"issuer/+/json",
				"issuers/", // LIST operations append a '/' to the requested path
				"ocsp",     // OCSP POST
				"ocsp/*",   // OCSP GET

				// ACME paths are added below
			},

			LocalStorage: []string{
				revokedPath,
				localDeltaWALPath,
				legacyCRLPath,
				clusterConfigPath,
				"crls/",
				"certs/",
				acmePathPrefix,
			},

			Root: []string{
				"root",
				"root/sign-self-issued",
			},

			SealWrapStorage: []string{
				legacyCertBundlePath,
				legacyCertBundleBackupPath,
				keyPrefix,
			},
		},

		Paths: []*framework.Path{
			pathListRoles(&b),
			pathRoles(&b),
			pathListCelRoles(&b),
			pathCelRoles(&b),
			pathCelIssue(&b),
			pathCelSign(&b),
			pathGenerateRoot(&b),
			pathSignIntermediate(&b),
			pathSignSelfIssued(&b),
			pathDeleteRoot(&b),
			pathGenerateIntermediate(&b),
			pathSetSignedIntermediate(&b),
			pathConfigCA(&b),
			pathConfigCRL(&b),
			pathConfigURLs(&b),
			pathConfigCluster(&b),
			pathSignVerbatim(&b),
			pathSign(&b),
			pathIssue(&b),
			pathRotateCRL(&b),
			pathRotateDeltaCRL(&b),
			pathRevoke(&b),
			pathRevokeWithKey(&b),
			pathListCertsRevoked(&b),
			pathTidy(&b),
			pathTidyCancel(&b),
			pathTidyStatus(&b),
			pathConfigAutoTidy(&b),

			// Issuer APIs
			pathListIssuers(&b),
			pathGetIssuer(&b),
			pathGetUnauthedIssuer(&b),
			pathGetIssuerCRL(&b),
			pathImportIssuer(&b),
			pathIssuerIssue(&b),
			pathIssuerSign(&b),
			pathIssuerSignIntermediate(&b),
			pathIssuerSignSelfIssued(&b),
			pathIssuerSignVerbatim(&b),
			pathIssuerGenerateRoot(&b),
			pathRotateRoot(&b),
			pathIssuerGenerateIntermediate(&b),
			pathCrossSignIntermediate(&b),
			pathConfigIssuers(&b),
			pathReplaceRoot(&b),
			pathRevokeIssuer(&b),

			// Key APIs
			pathListKeys(&b),
			pathKey(&b),
			pathGenerateKey(&b),
			pathImportKey(&b),
			pathConfigKeys(&b),

			// Fetch APIs have been lowered to favor the newer issuer API endpoints
			pathFetchCA(&b),
			pathFetchCAChain(&b),
			pathFetchCRL(&b),
			pathFetchCRLViaCertPath(&b),
			pathFetchValidRaw(&b),
			pathFetchValid(&b),
			pathFetchListCerts(&b),
			pathFetchListCertsDetailed(&b),

			// OCSP APIs
			buildPathOcspGet(&b),
			buildPathOcspPost(&b),

			// CRL Signing
			pathResignCrls(&b),
			pathSignRevocationList(&b),

			// ACME
			pathAcmeConfig(&b),
			pathAcmeEabList(&b),
			pathAcmeEabDelete(&b),
		},

		Secrets: []*framework.Secret{
			secretCerts(&b),
		},

		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initialize,
		Invalidate:     b.invalidate,
		PeriodicFunc:   b.periodicFunc,
		Clean:          b.cleanup,
	}

	// Add ACME paths to backend
	var acmePaths []*framework.Path
	acmePaths = append(acmePaths, pathAcmeDirectory(&b)...)
	acmePaths = append(acmePaths, pathAcmeNonce(&b)...)
	acmePaths = append(acmePaths, pathAcmeNewAccount(&b)...)
	acmePaths = append(acmePaths, pathAcmeUpdateAccount(&b)...)
	acmePaths = append(acmePaths, pathAcmeGetOrder(&b)...)
	acmePaths = append(acmePaths, pathAcmeListOrders(&b)...)
	acmePaths = append(acmePaths, pathAcmeNewOrder(&b)...)
	acmePaths = append(acmePaths, pathAcmeFinalizeOrder(&b)...)
	acmePaths = append(acmePaths, pathAcmeFetchOrderCert(&b)...)
	acmePaths = append(acmePaths, pathAcmeChallenge(&b)...)
	acmePaths = append(acmePaths, pathAcmeAuthorization(&b)...)
	acmePaths = append(acmePaths, pathAcmeRevoke(&b)...)
	acmePaths = append(acmePaths, pathAcmeNewEab(&b)...) // auth'd API that lives underneath the various /acme paths

	for _, acmePath := range acmePaths {
		b.Backend.Paths = append(b.Backend.Paths, acmePath)
	}

	// Add specific un-auth'd paths for ACME APIs
	for _, acmePrefix := range []string{"", "issuer/+/", "roles/+/", "issuer/+/roles/+/"} {
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/directory")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/new-nonce")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/new-account")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/new-order")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/revoke-cert")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/key-change")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/account/+")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/authorization/+")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/challenge/+/+")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/orders")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/order/+")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/order/+/finalize")
		b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, acmePrefix+"acme/order/+/cert")
		// We specifically do NOT add acme/new-eab to this as it should be auth'd
	}

	b.tidyCASGuard = new(uint32)
	b.tidyCancelCAS = new(uint32)
	b.tidyStatus = &tidyStatus{state: tidyStatusInactive}
	b.storage = conf.StorageView
	b.backendUUID = conf.BackendUUID

	b.pkiStorageVersion.Store(0)

	// b isn't yet initialized with SystemView state; calling b.System() will
	// result in a nil pointer dereference. Instead query BackendConfig's
	// copy of SystemView.
	cannotRebuildCRLs := conf.System.ReplicationState().HasState(consts.ReplicationPerformanceStandby) ||
		conf.System.ReplicationState().HasState(consts.ReplicationDRSecondary)
	b.crlBuilder = newCRLBuilder(!cannotRebuildCRLs)

	// Delay the first tidy until after we've started up.
	b.lastTidy = time.Now()

	// Metrics initialization for count of certificates in storage
	b.certCountEnabled = &atomic.Bool{}
	b.publishCertCountMetrics = &atomic.Bool{}
	b.certsCounted = &atomic.Bool{}
	b.certCountError = "Initialize Not Yet Run, Cert Counts Unavailable"
	b.certCount = &atomic.Uint32{}
	b.revokedCertCount = &atomic.Uint32{}
	b.possibleDoubleCountedSerials = make([]string, 0, 250)
	b.possibleDoubleCountedRevokedSerials = make([]string, 0, 250)

	b.acmeState = NewACMEState()
	return &b
}

type backend struct {
	*framework.Backend

	backendUUID       string
	storage           logical.Storage
	revokeStorageLock sync.RWMutex
	tidyCASGuard      *uint32
	tidyCancelCAS     *uint32

	tidyStatusLock sync.RWMutex
	tidyStatus     *tidyStatus
	lastTidy       time.Time

	certCountEnabled                    *atomic.Bool
	publishCertCountMetrics             *atomic.Bool
	certCount                           *atomic.Uint32
	revokedCertCount                    *atomic.Uint32
	certsCounted                        *atomic.Bool
	certCountError                      string
	possibleDoubleCountedSerials        []string
	possibleDoubleCountedRevokedSerials []string

	pkiStorageVersion atomic.Value
	crlBuilder        *crlBuilder

	// Write lock around issuers and keys.
	issuersLock sync.RWMutex

	// Context around ACME operations
	acmeState       *acmeState
	acmeAccountLock sync.RWMutex // (Write) Locked on Tidy, (Read) Locked on Account Creation
	// TODO: Stress test this - eg. creating an order while an account is being revoked
}

type roleOperation func(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error)

const backendHelp = `
The PKI backend dynamically generates X509 server and client certificates.

After mounting this backend, configure the CA using the "pem_bundle" endpoint within
the "config/" path.
`

func metricsKey(req *logical.Request, extra ...string) []string {
	if req == nil || req.MountPoint == "" {
		return extra
	}
	key := make([]string, len(extra)+1)
	key[0] = req.MountPoint[:len(req.MountPoint)-1]
	copy(key[1:], extra)
	return key
}

func (b *backend) metricsWrap(callType string, roleMode int, ofunc roleOperation) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := metricsKey(req, callType)
		var role *roleEntry
		var labels []metrics.Label
		var err error

		var roleName string
		switch roleMode {
		case roleRequired:
			roleName = data.Get("role").(string)
		case roleOptional:
			r, ok := data.GetOk("role")
			if ok {
				roleName = r.(string)
			}
		}
		if roleMode > noRole {
			// Get the role
			role, err = b.getRole(ctx, req.Storage, roleName)
			if err != nil {
				return nil, err
			}
			if role == nil && (roleMode == roleRequired || len(roleName) > 0) {
				return logical.ErrorResponse("unknown role: %s", roleName), nil
			}
			labels = []metrics.Label{{Name: "role", Value: roleName}}
		}

		ns, err := namespace.FromContext(ctx)
		if err == nil {
			labels = append(labels, metricsutil.NamespaceLabel(ns))
		}

		start := time.Now()
		defer metrics.MeasureSinceWithLabels(key, start, labels)
		resp, err := ofunc(ctx, req, data, role)

		if err != nil || resp.IsError() {
			metrics.IncrCounterWithLabels(append(key, "failure"), 1.0, labels)
		} else {
			metrics.IncrCounterWithLabels(key, 1.0, labels)
		}
		return resp, err
	}
}

// initialize is used to perform a possible PKI storage migration if needed
func (b *backend) initialize(ctx context.Context, _ *logical.InitializationRequest) error {
	sc := b.makeStorageContext(ctx, b.storage)
	if err := b.crlBuilder.reloadConfigIfRequired(sc); err != nil {
		return err
	}

	err := b.initializePKIIssuersStorage(ctx)
	if err != nil {
		return err
	}

	err = b.acmeState.Initialize(b, sc)
	if err != nil {
		return err
	}

	// Initialize also needs to populate our certificate and revoked certificate count
	err = b.initializeStoredCertificateCounts(ctx)
	if err != nil {
		// Don't block/err initialize/startup for metrics.  Context on this call can time out due to number of certificates.
		b.Logger().Error("Could not initialize stored certificate counts", "error", err)
		b.certCountError = err.Error()
	}

	return nil
}

func (b *backend) cleanup(_ context.Context) {
	b.acmeState.Shutdown(b)
}

func (b *backend) initializePKIIssuersStorage(ctx context.Context) error {
	// Grab the lock prior to the updating of the storage lock preventing us flipping
	// the storage flag midway through the request stream of other requests.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// Load up our current pki storage state, no matter the host type we are on.
	b.updatePkiStorageVersion(ctx, false)

	// Early exit if not a primary cluster or performance secondary with a local mount.
	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary|consts.ReplicationPerformanceStandby) ||
		(!b.System().LocalMount() && b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		b.Logger().Debug("skipping PKI migration as we are not on primary or secondary with a local mount")
		return nil
	}

	if err := migrateStorage(ctx, b, b.storage); err != nil {
		b.Logger().Error("Error during migration of PKI mount: " + err.Error())
		return err
	}

	b.updatePkiStorageVersion(ctx, false)

	return nil
}

func (b *backend) useLegacyBundleCaStorage() bool {
	// This helper function is here to choose whether or not we use the newer
	// issuer/key storage format or the older legacy ca bundle format.
	//
	// This happens because we might've upgraded secondary PR clusters to
	// newer vault code versions. We still want to be able to service requests
	// with the old bundle format (e.g., issuing and revoking certs), until
	// the primary cluster's active node is upgraded to the newer Vault version
	// and the storage is migrated to the new format.
	version := b.pkiStorageVersion.Load()
	return version == nil || version == 0
}

func (b *backend) updatePkiStorageVersion(ctx context.Context, grabIssuersLock bool) {
	info, err := getMigrationInfo(ctx, b.storage)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("Failed loading PKI migration status, staying in legacy mode: %v", err))
		return
	}

	// If this method is called outside the initialize function, like say an
	// invalidate func on a performance replica cluster, we should be grabbing
	// the issuers lock to offer a consistent view of the storage version while
	// other events are processing things. Its unknown what might happen during
	// a single event if one part thinks we are in legacy mode, and then later
	// on we aren't.
	if grabIssuersLock {
		b.issuersLock.Lock()
		defer b.issuersLock.Unlock()
	}

	if info.isRequired {
		b.pkiStorageVersion.Store(0)
	} else {
		b.pkiStorageVersion.Store(1)
	}
}

func (b *backend) invalidate(ctx context.Context, key string) {
	switch {
	case strings.HasPrefix(key, legacyMigrationBundleLogKey):
		// This is for a secondary cluster to pick up that the migration has completed
		// and reset its compatibility mode and rebuild the CRL locally. Kick it off
		// as a go routine to not block this call due to the lock grabbing
		// within updatePkiStorageVersion.
		go func() {
			b.Logger().Info("Detected a migration completed, resetting pki storage version")
			b.updatePkiStorageVersion(ctx, true)
			b.crlBuilder.requestRebuildIfActiveNode(b)
		}()
	case strings.HasPrefix(key, issuerPrefix):
		if !b.useLegacyBundleCaStorage() {
			// See note in updateDefaultIssuerId about why this is necessary.
			// We do this ahead of CRL rebuilding just so we know that things
			// are stale.
			b.crlBuilder.invalidateCRLBuildTime()

			// If an issuer has changed on the primary, we need to schedule an update of our CRL,
			// the primary cluster would have done it already, but the CRL is cluster specific so
			// force a rebuild of ours.
			b.crlBuilder.requestRebuildIfActiveNode(b)
		} else {
			b.Logger().Debug("Ignoring invalidation updates for issuer as the PKI migration has yet to complete.")
		}
	case key == "config/crl":
		// We may need to reload our OCSP status flag
		b.crlBuilder.markConfigDirty()
	case key == storageAcmeConfig:
		b.acmeState.markConfigDirty()
	case key == storageIssuerConfig:
		b.crlBuilder.invalidateCRLBuildTime()
	}
}

func (b *backend) periodicFunc(ctx context.Context, request *logical.Request) error {
	sc := b.makeStorageContext(ctx, request.Storage)

	doCRL := func() error {
		// First attempt to reload the CRL configuration.
		if err := b.crlBuilder.reloadConfigIfRequired(sc); err != nil {
			return err
		}

		// As we're (below) modifying the backing storage, we need to ensure
		// we're not on a standby/secondary node.
		if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) ||
			b.System().ReplicationState().HasState(consts.ReplicationDRSecondary) {
			return nil
		}

		// Check if we're set to auto rebuild and a CRL is set to expire.
		if err := b.crlBuilder.checkForAutoRebuild(sc); err != nil {
			return err
		}

		// Then attempt to rebuild the CRLs if required.
		warnings, err := b.crlBuilder.rebuildIfForced(sc)
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			msg := "During rebuild of complete CRL, got the following warnings:"
			for index, warning := range warnings {
				msg = fmt.Sprintf("%v\n %d. %v", msg, index+1, warning)
			}
			b.Logger().Warn(msg)
		}

		// If a delta CRL was rebuilt above as part of the complete CRL rebuild,
		// this will be a no-op. However, if we do need to rebuild delta CRLs,
		// this would cause us to do so.
		warnings, err = b.crlBuilder.rebuildDeltaCRLsIfForced(sc, false)
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			msg := "During rebuild of delta CRL, got the following warnings:"
			for index, warning := range warnings {
				msg = fmt.Sprintf("%v\n %d. %v", msg, index+1, warning)
			}
			b.Logger().Warn(msg)
		}

		return nil
	}

	doAutoTidy := func() error {
		// As we're (below) modifying the backing storage, we need to ensure
		// we're not on a standby/secondary node.
		if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) ||
			b.System().ReplicationState().HasState(consts.ReplicationDRSecondary) {
			return nil
		}

		config, err := sc.getAutoTidyConfig()
		if err != nil {
			return err
		}

		if !config.Enabled || config.Interval <= 0*time.Second {
			return nil
		}

		// Check if we should run another tidy...
		now := time.Now()
		b.tidyStatusLock.RLock()
		nextOp := b.lastTidy.Add(config.Interval)
		b.tidyStatusLock.RUnlock()
		if now.Before(nextOp) {
			return nil
		}

		// Ensure a tidy isn't already running... If it is, we'll trigger
		// again when the running one finishes.
		if !atomic.CompareAndSwapUint32(b.tidyCASGuard, 0, 1) {
			return nil
		}

		// Prevent ourselves from starting another tidy operation while
		// this one is still running. This operation runs in the background
		// and has a separate error reporting mechanism.
		b.tidyStatusLock.Lock()
		b.lastTidy = now
		b.tidyStatusLock.Unlock()

		// Because the request from the parent storage will be cleared at
		// some point (and potentially reused) -- due to tidy executing in
		// a background goroutine -- we need to copy the storage entry off
		// of the backend instead.
		backendReq := &logical.Request{
			Storage: b.storage,
		}

		b.startTidyOperation(backendReq, config)
		return nil
	}

	// First tidy any ACME nonces to free memory.
	b.acmeState.DoTidyNonces()

	// Then run the CRL rebuild and tidy operation.
	crlErr := doCRL()
	tidyErr := doAutoTidy()

	// Periodically re-emit gauges so that they don't disappear/go stale
	tidyConfig, err := sc.getAutoTidyConfig()
	if err != nil {
		return err
	}
	b.emitCertStoreMetrics(tidyConfig)

	var errors error
	if crlErr != nil {
		errors = multierror.Append(errors, fmt.Errorf("Error building CRLs:\n - %w\n", crlErr))
	}

	if tidyErr != nil {
		errors = multierror.Append(errors, fmt.Errorf("Error running auto-tidy:\n - %w\n", tidyErr))
	}

	if errors != nil {
		return errors
	}

	// Check if the CRL was invalidated due to issuer swap and update
	// accordingly.
	if err := b.crlBuilder.flushCRLBuildTimeInvalidation(sc); err != nil {
		return err
	}

	// All good!
	return nil
}

func (b *backend) initializeStoredCertificateCounts(ctx context.Context) error {
	// For performance reasons, we can't lock on issuance/storage of certs until a list operation completes,
	// but we want to limit possible miscounts / double-counts to over-counting, so we take the tidy lock which
	// prevents (most) deletions - in particular we take a read lock (sufficient to block the write lock in
	// tidyStatusStart while allowing tidy to still acquire a read lock to report via its endpoint)
	b.tidyStatusLock.RLock()
	defer b.tidyStatusLock.RUnlock()
	sc := b.makeStorageContext(ctx, b.storage)
	config, err := sc.getAutoTidyConfig()
	if err != nil {
		return err
	}

	b.certCountEnabled.Store(config.MaintainCount)
	b.publishCertCountMetrics.Store(config.PublishMetrics)

	if config.MaintainCount == false {
		b.possibleDoubleCountedRevokedSerials = nil
		b.possibleDoubleCountedSerials = nil
		b.certsCounted.Store(true)
		b.certCount.Store(0)
		b.revokedCertCount.Store(0)
		b.certCountError = "Cert Count is Disabled: enable via Tidy Config maintain_stored_certificate_counts"
		return nil
	}

	// Ideally these three things would be set in one transaction, since that isn't possible, set the counts to "0",
	// first, so count will over-count (and miss putting things in deduplicate queue), rather than under-count.
	b.certCount.Store(0)
	b.revokedCertCount.Store(0)
	b.possibleDoubleCountedRevokedSerials = nil
	b.possibleDoubleCountedSerials = nil
	// A cert issued or revoked here will be double-counted.  That's okay, this is "best effort" metrics.
	b.certsCounted.Store(false)

	entries, err := b.storage.List(ctx, "certs/")
	if err != nil {
		return err
	}
	b.certCount.Add(uint32(len(entries)))

	revokedEntries, err := b.storage.List(ctx, "revoked/")
	if err != nil {
		return err
	}
	b.revokedCertCount.Add(uint32(len(revokedEntries)))

	b.certsCounted.Store(true)
	// Now that the metrics are set, we can switch from appending newly-stored certificates to the possible double-count
	// list, and instead have them update the counter directly.  We need to do this so that we are looking at a static
	// slice of possibly double counted serials.  Note that certsCounted is computed before the storage operation, so
	// there may be some delay here.

	// Sort the listed-entries first, to accommodate that delay.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i] < entries[j]
	})

	sort.Slice(revokedEntries, func(i, j int) bool {
		return revokedEntries[i] < revokedEntries[j]
	})

	// We assume here that these lists are now complete.
	sort.Slice(b.possibleDoubleCountedSerials, func(i, j int) bool {
		return b.possibleDoubleCountedSerials[i] < b.possibleDoubleCountedSerials[j]
	})

	listEntriesIndex := 0
	possibleDoubleCountIndex := 0
	for {
		if listEntriesIndex >= len(entries) {
			break
		}
		if possibleDoubleCountIndex >= len(b.possibleDoubleCountedSerials) {
			break
		}
		if entries[listEntriesIndex] == b.possibleDoubleCountedSerials[possibleDoubleCountIndex] {
			// This represents a double-counted entry
			b.decrementTotalCertificatesCountNoReport()
			listEntriesIndex = listEntriesIndex + 1
			possibleDoubleCountIndex = possibleDoubleCountIndex + 1
			continue
		}
		if entries[listEntriesIndex] < b.possibleDoubleCountedSerials[possibleDoubleCountIndex] {
			listEntriesIndex = listEntriesIndex + 1
			continue
		}
		if entries[listEntriesIndex] > b.possibleDoubleCountedSerials[possibleDoubleCountIndex] {
			possibleDoubleCountIndex = possibleDoubleCountIndex + 1
			continue
		}
	}

	sort.Slice(b.possibleDoubleCountedRevokedSerials, func(i, j int) bool {
		return b.possibleDoubleCountedRevokedSerials[i] < b.possibleDoubleCountedRevokedSerials[j]
	})

	listRevokedEntriesIndex := 0
	possibleRevokedDoubleCountIndex := 0
	for {
		if listRevokedEntriesIndex >= len(revokedEntries) {
			break
		}
		if possibleRevokedDoubleCountIndex >= len(b.possibleDoubleCountedRevokedSerials) {
			break
		}
		if revokedEntries[listRevokedEntriesIndex] == b.possibleDoubleCountedRevokedSerials[possibleRevokedDoubleCountIndex] {
			// This represents a double-counted revoked entry
			b.decrementTotalRevokedCertificatesCountNoReport()
			listRevokedEntriesIndex = listRevokedEntriesIndex + 1
			possibleRevokedDoubleCountIndex = possibleRevokedDoubleCountIndex + 1
			continue
		}
		if revokedEntries[listRevokedEntriesIndex] < b.possibleDoubleCountedRevokedSerials[possibleRevokedDoubleCountIndex] {
			listRevokedEntriesIndex = listRevokedEntriesIndex + 1
			continue
		}
		if revokedEntries[listRevokedEntriesIndex] > b.possibleDoubleCountedRevokedSerials[possibleRevokedDoubleCountIndex] {
			possibleRevokedDoubleCountIndex = possibleRevokedDoubleCountIndex + 1
			continue
		}
	}

	b.possibleDoubleCountedRevokedSerials = nil
	b.possibleDoubleCountedSerials = nil

	b.emitCertStoreMetrics(config)

	b.certCountError = ""

	return nil
}

func (b *backend) emitCertStoreMetrics(config *tidyConfig) {
	if config.PublishMetrics == true {
		certCount := b.certCount.Load()
		b.emitTotalCertCountMetric(certCount)
		revokedCertCount := b.revokedCertCount.Load()
		b.emitTotalRevokedCountMetric(revokedCertCount)
	}
}

// The "certsCounted" boolean here should be loaded from the backend certsCounted before the corresponding storage call:
// eg. certsCounted := b.certsCounted.Load()
func (b *backend) ifCountEnabledIncrementTotalCertificatesCount(certsCounted bool, newSerial string) {
	if b.certCountEnabled.Load() {
		certCount := b.certCount.Add(1)
		switch {
		case !certsCounted:
			// This is unsafe, but a good best-attempt
			newSerial = strings.TrimPrefix(newSerial, "certs/")
			b.possibleDoubleCountedSerials = append(b.possibleDoubleCountedSerials, newSerial)
		default:
			if b.publishCertCountMetrics.Load() {
				b.emitTotalCertCountMetric(certCount)
			}
		}
	}
}

func (b *backend) ifCountEnabledDecrementTotalCertificatesCountReport() {
	if b.certCountEnabled.Load() {
		certCount := b.decrementTotalCertificatesCountNoReport()
		if b.publishCertCountMetrics.Load() {
			b.emitTotalCertCountMetric(certCount)
		}
	}
}

func (b *backend) emitTotalCertCountMetric(certCount uint32) {
	metrics.SetGauge([]string{"secrets", "pki", b.backendUUID, "total_certificates_stored"}, float32(certCount))
}

// Called directly only by the initialize function to deduplicate the count, when we don't have a full count yet
// Does not respect whether-we-are-counting backend information.
func (b *backend) decrementTotalCertificatesCountNoReport() uint32 {
	newCount := b.certCount.Add(^uint32(0))
	return newCount
}

// The "certsCounted" boolean here should be loaded from the backend certsCounted before the corresponding storage call:
// eg. certsCounted := b.certsCounted.Load()
func (b *backend) ifCountEnabledIncrementTotalRevokedCertificatesCount(certsCounted bool, newSerial string) {
	if b.certCountEnabled.Load() {
		newRevokedCertCount := b.revokedCertCount.Add(1)
		switch {
		case !certsCounted:
			// This is unsafe, but a good best-attempt
			// allow passing in the path (revoked/serial) OR the serial
			newSerial = strings.TrimPrefix(newSerial, "revoked/")
			b.possibleDoubleCountedRevokedSerials = append(b.possibleDoubleCountedRevokedSerials, newSerial)
		default:
			if b.publishCertCountMetrics.Load() {
				b.emitTotalRevokedCountMetric(newRevokedCertCount)
			}
		}
	}
}

func (b *backend) ifCountEnabledDecrementTotalRevokedCertificatesCountReport() {
	if b.certCountEnabled.Load() {
		revokedCertCount := b.decrementTotalRevokedCertificatesCountNoReport()
		if b.publishCertCountMetrics.Load() {
			b.emitTotalRevokedCountMetric(revokedCertCount)
		}
	}
}

func (b *backend) emitTotalRevokedCountMetric(revokedCertCount uint32) {
	metrics.SetGauge([]string{"secrets", "pki", b.backendUUID, "total_revoked_certificates_stored"}, float32(revokedCertCount))
}

// Called directly only by the initialize function to deduplicate the count, when we don't have a full count yet
// Does not respect whether-we-are-counting backend information.
func (b *backend) decrementTotalRevokedCertificatesCountNoReport() uint32 {
	newRevokedCertCount := b.revokedCertCount.Add(^uint32(0))
	return newRevokedCertCount
}
