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

	// AuthzHeaderName is the name of header indication the authorization information
	AuthzHeaderName = "Authorization"

	// RequestHeaderName is the name of the header used by the Agent for
	// SSRF protection.
	RequestHeaderName = "X-Vault-Request"

	// HostNameHeader is the header containing the hostname information for the Vault server
	// This is used for server identification and logging purposes
	HostNameHeader = "X-Vault-Hostname"

	// RaftNodeIDHeader is the header containing the Raft node ID for distributed Vault clusters
	// Used in Raft consensus protocol for node identification and leader election
	RaftNodeIDHeader = "X-Vault-Raft-Node-ID"

	// RawErrorHeader is the header for raw error information that bypasses error formatting
	// Allows clients to receive unprocessed error details for debugging purposes
	RawErrorHeader = "X-Vault-Raw-Error"

	// WrapTTLHeader is the header for response wrapping TTL (Time To Live)
	// Specifies how long a wrapped response should be valid before automatic unwrapping
	WrapTTLHeader = "X-Vault-Wrap-TTL"

	// MFAHeader is the header for multi-factor authentication credentials
	// Used to pass MFA challenge responses during authentication
	MFAHeader = "X-Vault-MFA"

	// PolicyOverrideHeader is the header for policy override requests
	// Allows privileged users to bypass soft-mandatory Sentinel policies (RGPs and EGPs)
	PolicyOverrideHeader = "X-Vault-Policy-Override"

	// RequestedWithHeader is a standard HTTP header indicating the type of client making the request
	// Used for AJAX requests and client identification
	RequestedWithHeader = "X-Requested-With"

	// AWSIAMServerIDHeader is the header containing the AWS IAM server ID for AWS authentication
	// Used in AWS IAM authentication method to identify the server making the request
	AWSIAMServerIDHeader = "X-Vault-AWS-IAM-Server-ID"

	// NoRequestForwardingHeader prevents request forwarding in Vault clusters
	// Ensures requests are processed locally and not forwarded to other nodes
	NoRequestForwardingHeader = "X-Vault-No-Request-Forwarding"

	// WrapFormatHeader is the header for specifying the format of the wrapped response
	// Allows clients to request a specific format (e.g., JSON) for response wrapping
	WrapFormatHeader = "X-Vault-Wrap-Format"

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
)
