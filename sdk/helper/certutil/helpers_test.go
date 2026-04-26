package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/stretchr/testify/assert"
)

func TestGetHexFormatted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		desc    string
		input   []byte
		sep     string
		wantOut string
	}{
		{
			desc:    "nil input",
			input:   nil,
			sep:     "",
			wantOut: "",
		},
		{
			desc:    "Empty input",
			input:   []byte(""),
			sep:     "",
			wantOut: "",
		},
		{
			desc:    "Single character",
			input:   []byte{0x61},
			sep:     ":",
			wantOut: "61",
		},
		{
			desc:    "Multiple bytes",
			input:   []byte{0x61, 0x62, 0x63, 0x64},
			sep:     ":",
			wantOut: "61:62:63:64",
		},
		{
			desc:    "Leading 0s",
			input:   []byte{0x00, 0x01, 0x02, 0x0f},
			sep:     ":",
			wantOut: "00:01:02:0f",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := GetHexFormatted(tc.input, tc.sep)

			assert.Equal(t, tc.wantOut, got)
		})
	}
}

func TestParseHexFormatted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		desc    string
		input   string
		sep     string
		wantOut []byte
	}{
		{
			desc:    "Empty input",
			input:   "",
			sep:     ":",
			wantOut: nil,
		},
		{
			desc:    "Single hexadecimal byte",
			input:   "0",
			sep:     "",
			wantOut: []byte{0x00},
		},
		{
			desc:    "Maximum hexadecimal value",
			input:   "f",
			sep:     "",
			wantOut: []byte{0xf},
		},
		{
			desc:    "Two bytes without separator",
			input:   "ff",
			sep:     "",
			wantOut: []byte{0xf, 0xf},
		},
		{
			desc:    "Two bytes with separator",
			input:   "0:1",
			sep:     ":",
			wantOut: []byte{0x00, 0x01},
		},
		{
			desc:    "Case sensitive",
			input:   "0:1:F",
			sep:     ":",
			wantOut: []byte{0x00, 0x01, 0x0f},
		},
		{
			desc:    "Invalid hexadecimal",
			input:   "0:z",
			sep:     ":",
			wantOut: nil,
		},
		{
			desc:    "Empty segments",
			input:   "0::1",
			sep:     ":",
			wantOut: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := ParseHexFormatted(tc.input, tc.sep)

			assert.Equal(t, tc.wantOut, got)
		})
	}
}

func TestGetSubjKeyID(t *testing.T) {
	t.Parallel()

	validPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	errInternal := errutil.InternalError{Err: "passed-in private key is nil"}

	testCases := []struct {
		desc       string
		privateKey crypto.Signer
		wantErr    bool
	}{
		{
			desc:       "Empty private key",
			privateKey: nil,
			wantErr:    true,
		},
		{
			// Actual behaviour tested on TestGetSubjectKeyID
			desc:       "Valid crypto signer",
			privateKey: validPrivKey,
			wantErr:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := GetSubjKeyID(tc.privateKey)

			if tc.wantErr {
				assert.ErrorIs(t, err, errInternal)
			} else {
				assert.NotErrorIs(t, err, errInternal)
			}
		})
	}
}

func TestGetSubjectKeyID(t *testing.T) {
	t.Parallel()

	// Invalid RSA public key
	invalidRsaPubKey := &rsa.PublicKey{
		N: nil,
		E: 65537,
	}

	// Happy path 1 - Valid RSA public key
	validRsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	validRsaPubKey := &validRsaPrivKey.PublicKey

	type pkcs1PublicKey struct {
		N *big.Int
		E int
	}

	publicKeyBytes, err := asn1.Marshal(pkcs1PublicKey{
		N: validRsaPubKey.N,
		E: validRsaPubKey.E,
	})
	assert.NoError(t, err)

	shaSum := sha1.Sum(publicKeyBytes)
	validRsaPubKeySkid := shaSum[:]

	// Happy path 2 - Valid ECDSA public key
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	ecdsaPubKey := &ecdsaPrivKey.PublicKey
	publicKeyBytes, err = ecdsaPubKey.Bytes()
	assert.NoError(t, err)

	publicKeyBytesSkidShaSum := sha1.Sum(publicKeyBytes)
	publicKeyBytesSkid := publicKeyBytesSkidShaSum[:]

	// Happy path 3 - Valid ED25519 key
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	ed25519PubKeySkidShaSum := sha1.Sum(ed25519PubKey)
	ed25519PubKeySkid := ed25519PubKeySkidShaSum[:]

	testCases := []struct {
		desc       string
		inputKey   interface{}
		wantSkid   []byte
		wantErr    bool
		wantErrMsg string
	}{
		{
			desc:       "Nil input key",
			inputKey:   nil,
			wantSkid:   nil,
			wantErr:    true,
			wantErrMsg: "unsupported public key type: ",
		},
		{
			desc:       "Unsupported public key type",
			inputKey:   "not-an-actual-key",
			wantSkid:   nil,
			wantErr:    true,
			wantErrMsg: "unsupported public key type: ",
		},
		{
			desc:       "Invalid RSA public key",
			inputKey:   invalidRsaPubKey,
			wantSkid:   nil,
			wantErr:    true,
			wantErrMsg: "error marshalling public key: ",
		},
		{
			desc:       "Valid RSA public key",
			inputKey:   validRsaPubKey,
			wantSkid:   validRsaPubKeySkid,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			desc:       "Valid ECDSA public key",
			inputKey:   ecdsaPubKey,
			wantSkid:   publicKeyBytesSkid,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			desc:       "Valid ED25519 public key",
			inputKey:   ed25519PubKey,
			wantSkid:   ed25519PubKeySkid,
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			skid, err := GetSubjectKeyID(tc.inputKey)

			assert.Equal(t, tc.wantSkid, skid)

			if tc.wantErr {
				assert.Error(t, err)

				var errInternal errutil.InternalError
				assert.ErrorAs(t, err, &errInternal)

				assert.Contains(t, err.Error(), tc.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
