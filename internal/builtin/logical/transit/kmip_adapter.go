package transit

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/sdk/v2/logical"

	kmiplib "github.com/ovh/kmip-go"
)

type transitAdapter struct {
	b *backend
	s logical.Storage
}

var (
	_ kmip.Adapter       = (*transitAdapter)(nil)
	_ kmip.CryptoAdapter = (*transitAdapter)(nil)
)

func (a *transitAdapter) AuthenticateCert(ctx context.Context, subjectDN string) (allowedOps []string, err error) {
	return nil, nil
}

// CreateKey creates new key. KMIP algorithm and bit length come directly from the request, adapter converts to specific type.
func (a *transitAdapter) CreateKey(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32) (string, error) {
	return "", nil
}

// ImportKey imports raw key material:
//   - symmetric: raw bytes
//   - asymmetric: PKCS8 DER
func (a *transitAdapter) ImportKey(ctx context.Context, alg kmiplib.CryptographicAlgorithm, bitlen int32, keyMaterial []byte) (string, error) {
	return "", nil
}

// GetKey retrieves key material for a given unique id.
func (a *transitAdapter) GetKey(ctx context.Context, id string) (kmiplib.Object, error) {
	return nil, nil
}

// GetAttributes returns KMIP attributes for a key. Returns all attributes if names is empty.
func (a *transitAdapter) GetAttributes(ctx context.Context, id string, names []kmiplib.AttributeName) ([]kmiplib.Attribute, error) {
	return nil, nil
}

// LocateKeys returns a []IDs of keys matching attrs.
// Returns only non-revoked keys, empty []attr means return all active keys.
func (a *transitAdapter) LocateKeys(ctx context.Context, attrs []kmiplib.Attribute) ([]string, error) {
	return nil, nil
}

// ActivateKey activates a key.
func (a *transitAdapter) ActivateKey(ctx context.Context, id string) error { return nil }

// RevokeKey marks a key as revoked.
func (a *transitAdapter) RevokeKey(ctx context.Context, id string) error { return nil }

// DestroyKey destroys a key permanently.
func (a *transitAdapter) DestroyKey(ctx context.Context, id string) error { return nil }

// Logger returns the logger for the backend.
func (a *transitAdapter) Logger() hclog.Logger { return a.b.Logger() }

func (a *transitAdapter) Encrypt(ctx context.Context, id string, plaintext []byte) ([]byte, error) {
	return nil, nil
}
func (a *transitAdapter) Decrypt(ctx context.Context, id string, ciphertext []byte) ([]byte, error) {
	return nil, nil
}
func (a *transitAdapter) Sign(ctx context.Context, id string, data []byte) ([]byte, error) {
	return nil, nil
}
func (a *transitAdapter) Verify(ctx context.Context, id string, data, signature []byte) (bool, error) {
	return false, nil
}
