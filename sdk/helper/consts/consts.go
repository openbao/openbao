// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package consts

const (
	// ExpirationRestoreWorkerCount specifies the number of workers to use while
	// restoring leases into the expiration manager
	ExpirationRestoreWorkerCount = 64

	// NamespaceHeaderName is the header set to specify which namespace the
	// request is indented for.
	NamespaceHeaderName = "X-Vault-Namespace"

	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName = "X-Vault-Token"

	// RequestHeaderName is the name of the header used by the Agent for
	// SSRF protection.
	RequestHeaderName = "X-Vault-Request"

	// PerformanceReplicationALPN is the negotiated protocol used for
	// performance replication.
	PerformanceReplicationALPN = "replication_v1"

	// DRReplicationALPN is the negotiated protocol used for dr replication.
	DRReplicationALPN = "replication_dr_v1"

	PerfStandbyALPN = "perf_standby_v1"

	RequestForwardingALPN = "req_fw_sb-act_v1"

	RaftStorageALPN = "raft_storage_v1"

	// ReplicationResolverALPN is the negotiated protocol used for
	// resolving replicaiton addresses
	ReplicationResolverALPN = "replication_resolver_v1"

	VaultEnableFilePermissionsCheckEnv = "BAO_ENABLE_FILE_PERMISSIONS_CHECK"

	VaultDisableUserLockout = "BAO_DISABLE_USER_LOCKOUT"

	PerformanceReplicationPathTarget = "performance"

	DRReplicationPathTarget = "dr"

	// Path to perform inline authentication against. Any authentication
	// performed must be single-request.
	InlineAuthPathHeaderName = "X-Vault-Inline-Auth-Path"

	// Request operation to perform inline authentication with. Defaults to
	// update.
	InlineAuthOperationHeaderName = "X-Vault-Inline-Auth-Operation"

	// Prefix of user-specified parameters sent to the endpoint specified
	// in InlineAuthPathHeaderName. Each parameter is a raw base64 url-safe
	// (without padding) encoded JSON object containing:
	//
	// { "key": <name>, "value": <value> }
	//
	// so that typing of the value and case sensitivity of the key can be
	// preserved. The remainder of the header value (after the trailing
	// dash) is ignored. Any repeated header keys result in request failure.
	InlineAuthParameterHeaderPrefix = "X-Vault-Inline-Auth-Parameter-"

	// Namespace to perform inline authentication with. Defaults to
	// the value of X-Vault-Namespace; can be combined with any potential
	// namespace in X-Vault-Inline-Auth-Path.
	InlineAuthNamespaceHeaderName = "X-Vault-Inline-Auth-Namespace"

	// Whether the response object is from the underlying auth method. This
	// is sometimes not a sufficient check as a 404s and server errors are
	// often returned without response bodies. But when a non-empty response
	// is given, this disambiguates inline auth from subsequent call responses.
	InlineAuthErrorResponseHeader = "X-Vault-Inline-Auth-Failed"
)
