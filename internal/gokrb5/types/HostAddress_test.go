package types

import (
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/addrtype"
	"github.com/stretchr/testify/assert"
)

func TestGetHostAddress(t *testing.T) {
	tests := []struct {
		str    string
		ipType int32
		hex    string
	}{
		{"192.168.1.100", addrtype.IPv4, "c0a80164"},
		{"127.0.0.1", addrtype.IPv4, "7f000001"},
		{"[fe80::1cf3:b43b:df29:d43e]", addrtype.IPv6, "fe800000000000001cf3b43bdf29d43e"},
	}
	for _, test := range tests {
		h, err := GetHostAddress(test.str + ":1234")
		if err != nil {
			t.Errorf("error getting host for %s: %v", test.str, err)
		}
		assert.Equal(t, test.ipType, h.AddrType, "wrong address type for %s", test.str)
		assert.Equal(t, test.hex, hex.EncodeToString(h.Address), "wrong address bytes for %s", test.str)
	}
}
