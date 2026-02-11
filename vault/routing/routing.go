package routing

const (
	// mountTableType is the value we expect to find for the mount table and
	// corresponding entries
	MountTableType = "mounts"

	// CredentialTableType is the value we expect to find for the credential
	// table and corresponding entries
	CredentialTableType = "auth"
)

// ListingVisibilityType represents the types for listing visibility
type ListingVisibilityType string

const (
	// ListingVisibilityDefault is the default value for listing visibility
	ListingVisibilityDefault ListingVisibilityType = ""
	// ListingVisibilityHidden is the hidden type for listing visibility
	ListingVisibilityHidden ListingVisibilityType = "hidden"
	// ListingVisibilityUnauth is the unauth type for listing visibility
	ListingVisibilityUnauth ListingVisibilityType = "unauth"

	// CredentialRoutePrefix is the mount prefix used for the router
	CredentialRoutePrefix = "auth/"

	MountPathSystem    = "sys/"
	MountPathIdentity  = "identity/"
	MountPathCubbyhole = "cubbyhole/"

	MountTypeSystem      = "system"
	MountTypeNSSystem    = "ns_system"
	MountTypeIdentity    = "identity"
	MountTypeNSIdentity  = "ns_identity"
	MountTypeCubbyhole   = "cubbyhole"
	MountTypePlugin      = "plugin"
	MountTypeKV          = "kv"
	MountTypeNSCubbyhole = "ns_cubbyhole"
	MountTypeToken       = "token"
	MountTypeNSToken     = "ns_token"
)
