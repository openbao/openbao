package transit

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
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

// POC: allow-all.
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

// === MAPPING ===

// keyTypeFor maps a KMIP CryptographicAlgorithm + bit length to a transit KeyType.
// The bool return indicates whether the key is asymmetric.
func keyTypeFor(alg kmiplib.CryptographicAlgorithm, bitlen int32) (keysutil.KeyType, bool, error) {
	switch alg {
	case kmiplib.CryptographicAlgorithmAES:
		switch bitlen {
		case 128:
			return keysutil.KeyType_AES128_GCM96, false, nil
		case 256:
			return keysutil.KeyType_AES256_GCM96, false, nil
		}

	case kmiplib.CryptographicAlgorithmChaCha20,
		kmiplib.CryptographicAlgorithmChaCha20Poly1305:
		if bitlen == 256 {
			return keysutil.KeyType_ChaCha20_Poly1305, false, nil
		}

	case kmiplib.CryptographicAlgorithmRSA:
		switch bitlen {
		case 2048:
			return keysutil.KeyType_RSA2048, true, nil
		case 3072:
			return keysutil.KeyType_RSA3072, true, nil
		case 4096:
			return keysutil.KeyType_RSA4096, true, nil
		}

	// KMIP uses ECDSA or generic EC; the curve is conveyed by the key size.
	case kmiplib.CryptographicAlgorithmECDSA,
		kmiplib.CryptographicAlgorithmEC:
		switch bitlen {
		case 256:
			return keysutil.KeyType_ECDSA_P256, true, nil
		case 384:
			return keysutil.KeyType_ECDSA_P384, true, nil
		case 521:
			return keysutil.KeyType_ECDSA_P521, true, nil
		}

	case kmiplib.CryptographicAlgorithmHMACSHA1,
		kmiplib.CryptographicAlgorithmHMACSHA224,
		kmiplib.CryptographicAlgorithmHMACSHA256,
		kmiplib.CryptographicAlgorithmHMACSHA384,
		kmiplib.CryptographicAlgorithmHMACSHA512:
		// transit HMAC accepts 256..4096 bits
		// see keysutil.HmacMinKeySize and keysutil.HmacMaxKeySize
		if bitlen >= 256 && bitlen <= 4096 && bitlen%8 == 0 {
			return keysutil.KeyType_HMAC, false, nil
		}
	}
	return 0, false, fmt.Errorf("unsupported alg=%v bitlen=%d", alg, bitlen)
}
