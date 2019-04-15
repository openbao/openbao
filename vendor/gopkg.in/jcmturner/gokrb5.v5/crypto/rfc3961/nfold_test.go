package rfc3961

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_nfold(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		n      int
		b      []byte
		folded string
	}{
		{64, []byte("012345"), "be072631276b1955"},
		{56, []byte("password"), "78a07b6caf85fa"},
		{64, []byte("Rough Consensus, and Running Code"), "bb6ed30870b7f0e0"},
		{168, []byte("password"), "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"},
		{192, []byte("MASSACHVSETTS INSTITVTE OF TECHNOLOGY"), "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"},
		{168, []byte("Q"), "518a54a215a8452a518a54a215a8452a518a54a215"},
		{168, []byte("ba"), "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"},
	}
	for _, test := range tests {
		assert.Equal(t, test.folded, hex.EncodeToString(Nfold(test.b, test.n)), "Folded not as expected")
	}
}
