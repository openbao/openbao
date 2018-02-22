package crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/common"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/rfc3962"
	"testing"
)

func TestAes128CtsHmacSha196_StringToKey(t *testing.T) {
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
		{1, "password", "ATHENA.MIT.EDUraeburn", "cdedb5281bb2f801565a1122b2563515", "42263c6e89f4fc28b8df68ee09799f15"},
		{2, "password", "ATHENA.MIT.EDUraeburn", "01dbee7f4a9e243e988b62c73cda935d", "c651bf29e2300ac27fa469d693bdda13"},
		{1200, "password", "ATHENA.MIT.EDUraeburn", "5c08eb61fdf71e4e4ec3cf6ba1f5512b", "4c01cd46d632d01e6dbe230a01ed642a"},
		{5, "password", s, "d1daa78615f287e6a1c8b120d7062a49", "e9b23d52273747dd5c35cb55be619d8e"},
		{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", "139c30c0966bc32ba55fdbf212530ac9", "59d1bb789a828b1aa54ef9c2883f69ed"},
		{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", "9ccad6d468770cd51b10e6a68721be61", "cb8005dc5f90179a7f02104c0018751d"},
		{50, s2, "EXAMPLE.COMpianist", "6b9cf26d45455a43a5b8bb276a403b39", "f149c1f2e154a73452d43e7fe62a56e5"},
	}
	var e Aes128CtsHmacSha96
	for i, test := range tests {

		assert.Equal(t, test.pbkdf2, hex.EncodeToString(rfc3962.StringToPBKDF2(test.phrase, test.salt, test.iterations, e)), "PBKDF2 not as expected")
		k, err := e.StringToKey(test.phrase, test.salt, common.IterationsToS2Kparams(uint32(test.iterations)))
		if err != nil {
			t.Errorf("Error in processing string to key for test %d: %v", i, err)
		}
		assert.Equal(t, test.key, hex.EncodeToString(k), "String to Key not as expected")

	}
}
