package crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/common"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/rfc8009"
	"testing"
)

func TestAes256CtsHmacSha384192_StringToKey(t *testing.T) {
	// Test vectors from RFC 8009 Appendix A
	// Random 16bytes in test vector as string
	r, _ := hex.DecodeString("10DF9DD783E5BC8ACEA1730E74355F61")
	s := string(r)
	var tests = []struct {
		iterations uint32
		phrase     string
		salt       string
		saltp      string
		key        string
	}{
		{32768, "password", s + "ATHENA.MIT.EDUraeburn", "6165733235362d6374732d686d61632d7368613338342d3139320010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e", "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467"},
	}
	var e Aes256CtsHmacSha384192
	for _, test := range tests {
		saltp := rfc8009.GetSaltP(test.salt, "aes256-cts-hmac-sha384-192")
		assert.Equal(t, test.saltp, hex.EncodeToString(([]byte(saltp))), "SaltP not as expected")

		k, _ := e.StringToKey(test.phrase, test.salt, common.IterationsToS2Kparams(test.iterations))
		assert.Equal(t, test.key, hex.EncodeToString(k), "String to Key not as expected")
	}
}

func TestAes256CtsHmacSha384192_DeriveKey(t *testing.T) {
	// Test vectors from RFC 8009 Appendix A
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var e Aes256CtsHmacSha384192
	k, err := e.DeriveKey(protocolBaseKey, common.GetUsageKc(testUsage))
	if err != nil {
		t.Fatalf("Error deriving checksum key: %v", err)
	}
	assert.Equal(t, "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d", hex.EncodeToString(k), "Checksum derived key not as epxected")
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKe(testUsage))
	if err != nil {
		t.Fatalf("Error deriving encryption key: %v", err)
	}
	assert.Equal(t, "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", hex.EncodeToString(k), "Encryption derived key not as epxected")
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKi(testUsage))
	if err != nil {
		t.Fatalf("Error deriving integrity key: %v", err)
	}
	assert.Equal(t, "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", hex.EncodeToString(k), "Integrity derived key not as epxected")
}

func TestAes256CtsHmacSha384192_Cypto(t *testing.T) {
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var tests = []struct {
		plain      string
		confounder string
		ke         string
		ki         string
		encrypted  string // AESOutput
		hash       string // TruncatedHMACOutput
		cipher     string // Ciphertext(AESOutput|HMACOutput)
	}{
		// Test vectors from RFC 8009 Appendix A
		{"", "f764e9fa15c276478b2c7d0c4e5f58e4", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "41f53fa5bfe7026d91faf9be959195a0", "58707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c", "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c"},
		{"000102030405", "b80d3251c1f6471494256ffe712d0b9a", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9", "f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2", "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2"},
		{"000102030405060708090a0b0c0d0e0f", "53bf8a0d105265d4e276428624ce5e63", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6", "8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266", "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266"},
		{"000102030405060708090a0b0c0d0e0f1011121314", "763e65367e864f02f55153c7e3b58af1", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86", "fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62", "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62"},
	}
	var e Aes256CtsHmacSha384192
	for i, test := range tests {
		m, _ := hex.DecodeString(test.plain)
		b, _ := hex.DecodeString(test.encrypted)
		ke, _ := hex.DecodeString(test.ke)
		cf, _ := hex.DecodeString(test.confounder)
		ct, _ := hex.DecodeString(test.cipher)
		cfm := append(cf, m...)

		// Test encryption to raw encrypted bytes
		_, c, err := e.EncryptData(ke, cfm)
		if err != nil {
			t.Errorf("Encryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.encrypted, hex.EncodeToString(c), "Encrypted result not as expected - test %v", i)

		// Test decryption of raw encrypted bytes
		p, err := e.DecryptData(ke, b)
		//Remove the confounder bytes
		p = p[e.GetConfounderByteSize():]
		if err != nil {
			t.Errorf("Decryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.plain, hex.EncodeToString(p), "Decrypted result not as expected - test %v", i)

		// Test integrity check of complete ciphertext message
		assert.True(t, e.VerifyIntegrity(protocolBaseKey, ct, ct, testUsage), "Integrity check of cipher text failed")

		// Test encrypting and decrypting a complete cipertext message (with confounder, integrity hash)
		_, cm, err := e.EncryptMessage(protocolBaseKey, m, testUsage)
		if err != nil {
			t.Errorf("Encryption to message failed for test %v: %v", i+1, err)
		}
		dm, err := e.DecryptMessage(protocolBaseKey, cm, testUsage)
		if err != nil {
			t.Errorf("Decrypting complete encrypted message failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, m, dm, "Message not as expected after encrypting and decrypting for test %v: %v", i+1, err)

		// Test the integrity hash
		ivz := make([]byte, e.GetConfounderByteSize())
		hm := append(ivz, b...)
		mac, _ := common.GetIntegrityHash(hm, protocolBaseKey, testUsage, e)
		assert.Equal(t, test.hash, hex.EncodeToString(mac), "HMAC result not as expected - test %v", i)
	}
}

func TestAes256CtsHmacSha384192_VerifyIntegrity(t *testing.T) {
	// Test vectors from RFC 8009
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var e Aes256CtsHmacSha384192
	var tests = []struct {
		kc     string
		pt     string
		chksum string
	}{
		{"ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d", "000102030405060708090a0b0c0d0e0f1011121314", "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a"},
	}
	for _, test := range tests {
		p, _ := hex.DecodeString(test.pt)
		b, err := e.GetChecksumHash(protocolBaseKey, p, testUsage)
		if err != nil {
			t.Errorf("Error generating checksum: %v", err)
		}
		assert.Equal(t, test.chksum, hex.EncodeToString(b), "Checksum not as expected")
	}
}
