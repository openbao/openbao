// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package consts

import (
	"github.com/openbao/openbao/api/v2"
)

const (
	// ExpirationRestoreWorkerCount specifies the number of workers to use while
	// restoring leases into the expiration manager
	ExpirationRestoreWorkerCount = 64

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

	// NamespaceHeaderName is the header set to specify which namespace the
	// request is intended for.
	NamespaceHeaderName = api.NamespaceHeaderName

	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName = api.AuthHeaderName

	// RequestHeaderName is the name of the header used by the Agent for
	// SSRF protection.
	RequestHeaderName = api.RequestHeaderName

	// NoRequestForwardingHeaderName is the name of the header telling Vault not
	// to use request forwarding.
	NoRequestForwardingHeaderName = api.NoRequestForwardingHeaderName

	// MFAHeaderName represents the HTTP header which carries the credentials
	// required to perform MFA on any path.
	MFAHeaderName = api.MFAHeaderName

	// WrapTTLHeaderName is the name of the header containing a directive to
	// wrap the response.
	WrapTTLHeaderName = api.WrapTTLHeaderName

	// RawErrorHeaderName is the name of the header that holds any errors that
	// occurred responding to requests to special endpoints that return raw
	// response bodies.
	RawErrorHeaderName = api.RawErrorHeaderName

	// HostnameHeaderName is the name of the header that holds the responding
	// node's hostname when enable_response_header_hostname is set in the server
	// configuration.
	HostnameHeaderName = api.HostnameHeaderName

	// RaftNodeIDHeaderName is the name of the header that holds the responding
	// node's Raft node ID if enable_response_header_raft_node_id is set in the
	// server configuration and the node is participating in a Raft cluster.
	RaftNodeIDHeaderName = api.RaftNodeIDHeaderName

	// WrapFormatHeaderName is the name of the header containing the format to
	// wrap in; has no effect if the wrap TTL is not set.
	WrapFormatHeaderName = api.WrapFormatHeaderName

	// Path to perform inline authentication against. Any authentication
	// performed must be single-request.
	InlineAuthPathHeaderName = api.InlineAuthPathHeaderName

	// Request operation to perform inline authentication with. Defaults to
	// update.
	InlineAuthOperationHeaderName = api.InlineAuthOperationHeaderName

	// Namespace to perform inline authentication with. Defaults to
	// the value of X-Vault-Namespace; can be combined with any potential
	// namespace in X-Vault-Inline-Auth-Path.
	InlineAuthNamespaceHeaderName = api.InlineAuthNamespaceHeaderName

	// Whether the response object is from the underlying auth method. This
	// is sometimes not a sufficient check as a 404s and server errors are
	// often returned without response bodies. But when a non-empty response
	// is given, this disambiguates inline auth from subsequent call responses.
	InlineAuthErrorResponseHeader = api.InlineAuthErrorResponseHeader

	// Prefix of user-specified parameters sent to the endpoint specified
	// in InlineAuthPathHeaderName. Each parameter is a raw base64 url-safe
	// (without padding) encoded JSON object containing:
	//
	// { "key": <name>, "value": <value> }
	//
	// so that typing of the value and case sensitivity of the key can be
	// preserved. The remainder of the header value (after the trailing
	// dash) is ignored. Any repeated header keys result in request failure.
	InlineAuthParameterHeaderPrefix = api.InlineAuthParameterHeaderPrefix
)
