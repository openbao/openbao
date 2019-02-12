package aescts

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesCts_Encrypt_Decrypt(t *testing.T) {
	iv := make([]byte, 16)
	key, _ := hex.DecodeString("636869636b656e207465726979616b69")
	var tests = []struct {
		plain  string
		cipher string
		nextIV string
	}{
		//Test vectors from RFC 3962 Appendix B
		{"4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97", "c6353568f2bf8cb4d8a580362da7ff7f"},
		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5", "fc00783e0efdb2c1d445d4c8eff7ed22"},
		{"4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584", "39312523a78662d5be7fcbcc98ebf5a8"},
		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5", "b3fffd940c16a18c1b5549d2f838029e"},
		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8", "9dad8bbb96c4cdc03bc103e1a194bbd8"},
		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8", "4807efe836ee89a526730dbc2f7bc840"},
	}
	for i, test := range tests {
		m, _ := hex.DecodeString(test.plain)
		niv, c, err := Encrypt(key, iv, m)
		if err != nil {
			t.Errorf("Encryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.cipher, hex.EncodeToString(c), "Encrypted result not as expected")
		assert.Equal(t, test.nextIV, hex.EncodeToString(niv), "Next state IV not as expected")
	}
	//t.Log("AES CTS Encryption tests finished")
	for i, test := range tests {
		b, _ := hex.DecodeString(test.cipher)
		p, err := Decrypt(key, iv, b)
		if err != nil {
			t.Errorf("Decryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.plain, hex.EncodeToString(p), "Decrypted result not as expected")
	}
	//t.Log("AES CTS Decryption tests finished")
}
