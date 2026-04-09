package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
)

// Adapter is an interface that OpenBao engine must implement to expose key management via KMIP.
type Adapter interface {
	// AuthenticateCert resolves a TLS client certificate Subject DN to a set of allowed operations and keys.
	// empty allow list == "nothing allowed", nil slices == "all allowed"
	AuthenticateCert(ctx context.Context, subjectDN string) (allowedOps []string, allowedKeys []string, err error)

	// CreateKey creates new key. KMIP algorithm and bit length come directly from the request, adapter converts to specific type.
	CreateKey(ctx context.Context, name string, alg kmip.CryptographicAlgorithm, bitlen int) (string, error)

	// ImportKey imports raw key material:
	//   - symmetric: raw bytes
	//   - asymmetric: PKCS8 DER
	ImportKey(ctx context.Context, name string, alg kmip.CryptographicAlgorithm, bitlen int, keyMaterial []byte) (string, error)

	// GetKey retrieves key material for a given unique id.
	GetKey(ctx context.Context, id string) (kmip.Object, error)

	// GetAttributes returns KMIP attributes for a key. Returns all attributes if names is empty.
	GetAttributes(ctx context.Context, id string, names []kmip.AttributeName) ([]kmip.Attribute, error)

	// LocateKeys returns a []IDs of keys matching attrs.
	// Returns only non-revoked keys, empty []attr means return all active keys.
	LocateKeys(ctx context.Context, attrs []kmip.Attribute) ([]string, error)

	// ActivateKey activates a key.
	ActivateKey(ctx context.Context, id string) error

	// RevokeKey marks a key as revoked.
	RevokeKey(ctx context.Context, id string) error

	// DestroyKey destroys a key permanently.
	DestroyKey(ctx context.Context, id string) error
}

// CryptoAdapter supports cryptographic operations. Server register Encrypt/Decrypt/Sign/Verify handlers.
type CryptoAdapter interface {
	Encrypt(ctx context.Context, id string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, id string, ciphertext []byte) ([]byte, error)
	Sign(ctx context.Context, id string, data []byte) ([]byte, error)
	Verify(ctx context.Context, id string, data, signature []byte) (bool, error)
}
