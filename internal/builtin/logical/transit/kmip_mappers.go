package transit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	kmiplib "github.com/ovh/kmip-go"
)

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

// kmipAttrsForPolicy returns KMIP attribute values for a transit policy key.
// For variable-length key types (HMAC) the bit length is derived from entry's
// key material — caller must pass the relevant KeyEntry.
func kmipAttrsForPolicy(kt keysutil.KeyType, entry keysutil.KeyEntry) (kmiplib.CryptographicAlgorithm, int32, kmiplib.ObjectType, error) {
	switch kt {
	case keysutil.KeyType_AES128_GCM96:
		return kmiplib.CryptographicAlgorithmAES, 128, kmiplib.ObjectTypeSymmetricKey, nil
	case keysutil.KeyType_AES256_GCM96:
		return kmiplib.CryptographicAlgorithmAES, 256, kmiplib.ObjectTypeSymmetricKey, nil
	case keysutil.KeyType_ChaCha20_Poly1305:
		return kmiplib.CryptographicAlgorithmChaCha20Poly1305, 256, kmiplib.ObjectTypeSymmetricKey, nil
	// ToDo: check KMIP defines no XChaCha20 variant ?
	case keysutil.KeyType_HMAC:
		// Transit HMAC is hash-agnostic. KMIP requires a specific variant.
		// Default to HMAC-SHA256.
		return kmiplib.CryptographicAlgorithmHMACSHA256, int32(len(entry.Key) * 8), kmiplib.ObjectTypeSymmetricKey, nil
	case keysutil.KeyType_RSA2048:
		return kmiplib.CryptographicAlgorithmRSA, 2048, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_RSA3072:
		return kmiplib.CryptographicAlgorithmRSA, 3072, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_RSA4096:
		return kmiplib.CryptographicAlgorithmRSA, 4096, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_ECDSA_P256:
		return kmiplib.CryptographicAlgorithmECDSA, 256, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_ECDSA_P384:
		return kmiplib.CryptographicAlgorithmECDSA, 384, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_ECDSA_P521:
		return kmiplib.CryptographicAlgorithmECDSA, 521, kmiplib.ObjectTypePrivateKey, nil
	case keysutil.KeyType_ED25519:
		// ToDo: ovh/kmip-go has no Ed25519 algorithm constant ?
		return 0, 0, 0, fmt.Errorf("Ed25519 has no KMIP algorithm in kmip-go")
	}
	return 0, 0, 0, fmt.Errorf("unsupported key type %v", kt)
}

func keyEntryToKmipObject(entry keysutil.KeyEntry, kt keysutil.KeyType) (kmiplib.Object, error) {
	alg, bitlen, objType, err := kmipAttrsForPolicy(kt, entry)
	if err != nil {
		return nil, err
	}
	switch objType {
	case kmiplib.ObjectTypeSymmetricKey:
		raw := append([]byte{}, entry.Key...)
		return &kmiplib.SymmetricKey{
			KeyBlock: kmiplib.KeyBlock{
				KeyFormatType: kmiplib.KeyFormatTypeRaw,
				KeyValue: &kmiplib.KeyValue{
					Plain: &kmiplib.PlainKeyValue{
						KeyMaterial: kmiplib.KeyMaterial{Bytes: &raw},
					},
				},
				CryptographicAlgorithm: alg,
				CryptographicLength:    bitlen,
			},
		}, nil
	case kmiplib.ObjectTypePrivateKey:
		var der []byte
		switch {
		case entry.RSAKey != nil:
			der, err = x509.MarshalPKCS8PrivateKey(entry.RSAKey)
			if err != nil {
				return nil, fmt.Errorf("marshal RSA private key: %w", err)
			}
		case entry.EC_D != nil:
			curve, cerr := curveForKeyType(kt)
			if cerr != nil {
				return nil, cerr
			}
			priv := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: curve, X: entry.EC_X, Y: entry.EC_Y},
				D:         entry.EC_D,
			}
			der, err = x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				return nil, fmt.Errorf("marshal EC private key: %w", err)
			}
		default:
			return nil, fmt.Errorf("private key material missing for %v", kt)
		}
		return &kmiplib.PrivateKey{
			KeyBlock: kmiplib.KeyBlock{
				KeyFormatType: kmiplib.KeyFormatTypePKCS_8,
				KeyValue: &kmiplib.KeyValue{
					Plain: &kmiplib.PlainKeyValue{
						KeyMaterial: kmiplib.KeyMaterial{Bytes: &der},
					},
				},
				CryptographicAlgorithm: alg,
				CryptographicLength:    bitlen,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported KMIP object type %v for key type %v", objType, kt)
}

func curveForKeyType(kt keysutil.KeyType) (elliptic.Curve, error) {
	switch kt {
	case keysutil.KeyType_ECDSA_P256:
		return elliptic.P256(), nil
	case keysutil.KeyType_ECDSA_P384:
		return elliptic.P384(), nil
	case keysutil.KeyType_ECDSA_P521:
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("no curve for key type %v", kt)
}
