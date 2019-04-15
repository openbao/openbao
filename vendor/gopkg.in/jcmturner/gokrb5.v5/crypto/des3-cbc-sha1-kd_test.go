package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDes3CbcSha1Kd_DR_DK(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 3961 Appendix A3
	var tests = []struct {
		key   string
		usage string
		dr    string
		dk    string
	}{
		{"dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92", "0000000155", "935079d14490a75c3093c4a6e8c3b049c71e6ee705", "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd"},
		{"5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2", "00000001aa", "9f58e5a047d894101c469845d67ae3c5249ed812f2", "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207"},
		{"98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc", "0000000155", "12fff90c773f956d13fc2ca0d0840349dbd39908eb", "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf"},
		{"622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5", "00000001aa", "f8debf05b097e7dc0603686aca35d91fd9a5516a70", "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e"},
		{"d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb", "6b65726265726f73", "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da", "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43"},
		{"c1081649ada74362e6a1459d01dfd30d67c2234c940704da", "0000000155", "348056ec98fcc517171d2b4d7a9493af482d999175", "348057ec98fdc48016161c2a4c7a943e92ae492c989175f7"},
		{"5d154af238f46713155719d55e2f1f790dd661f279a7917c", "00000001aa", "a8818bc367dadacbe9a6c84627fb60c294b01215e5", "a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1"},
		{"798562e049852f57dc8c343ba17f2ca1d97394efc8adc443", "0000000155", "c813f88b3be2b2f75424ce9175fbc8483b88c8713a", "c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49"},
		{"26dce334b545292f2feab9a8701a89a4b99eb9942cecd016", "00000001aa", "f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec", "f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d"},
	}
	for _, test := range tests {
		var e Des3CbcSha1Kd
		key, _ := hex.DecodeString(test.key)
		usage, _ := hex.DecodeString(test.usage)
		derivedRandom, err := e.DeriveRandom(key, usage)
		if err != nil {
			t.Fatal(fmt.Sprintf("Error in deriveRandom: %v", err))
		}
		assert.Equal(t, test.dr, hex.EncodeToString(derivedRandom), "DR not as expected")
		derivedKey, err := e.DeriveKey(key, usage)
		if err != nil {
			t.Fatal(fmt.Sprintf("Error in deriveKey: %v", err))
		}
		assert.Equal(t, test.dk, hex.EncodeToString(derivedKey), "DK not as expected")
	}
}

func TestDes3CbcSha1Kd_StringToKey(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		salt   string
		secret string
		key    string
	}{
		{"ATHENA.MIT.EDUraeburn", "password", "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e"},
		{"WHITEHOUSE.GOVdanny", "potatoe", "dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a"},
		{"EXAMPLE.COMbuckaroo", "penny", "6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a"},
		{"ATHENA.MIT.EDUJuri" + "\u0161" + "i" + "\u0107", "\u00DF", "16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0"},
		{"EXAMPLE.COMpianist", "𝄞", "85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"},
	}
	var e Des3CbcSha1Kd
	for _, test := range tests {
		key, err := e.StringToKey(test.secret, test.salt, "")
		if err != nil {
			t.Errorf("error in StringToKey: %v", err)
		}
		assert.Equal(t, test.key, hex.EncodeToString(key), "StringToKey not as expected")
	}
}
