package crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/common"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/rfc3962"
	"testing"
)

func TestAes256CtsHmacSha196_StringToKey(t *testing.T) {
	// Test vectors from RFC 3962 Appendix B
	b, _ := hex.DecodeString("1234567878563412")
	s := string(b)
	b, _ = hex.DecodeString("f09d849e")
	s2 := string(b)
	var tests = []struct {
		iterations int64
		phrase     string
		salt       string
		pbkdf2     string
		key        string
	}{
		{1, "password", "ATHENA.MIT.EDUraeburn", "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837", "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
		{2, "password", "ATHENA.MIT.EDUraeburn", "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86", "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
		{1200, "password", "ATHENA.MIT.EDUraeburn", "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13", "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"},
		{5, "password", s, "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee", "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31"},
		{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1", "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34"},
		{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a", "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b"},
		{50, s2, "EXAMPLE.COMpianist", "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52", "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e"},
	}
	var e Aes256CtsHmacSha96
	for i, test := range tests {

		assert.Equal(t, test.pbkdf2, hex.EncodeToString(rfc3962.StringToPBKDF2(test.phrase, test.salt, test.iterations, e)), "PBKDF2 not as expected")
		k, err := e.StringToKey(test.phrase, test.salt, common.IterationsToS2Kparams(uint32(test.iterations)))
		if err != nil {
			t.Errorf("Error in processing string to key for test %d: %v", i, err)
		}
		assert.Equal(t, test.key, hex.EncodeToString(k), "String to Key not as expected")

	}
}
