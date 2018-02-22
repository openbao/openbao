// +build integration
// To turn on this test use -tags=integration in go test command

package dnsutils

import (
	"github.com/stretchr/testify/assert"
	"strconv"
	"strings"
	"testing"
)

func TestResolveKDC(t *testing.T) {
	for i := 0; i < 100; i++ {
		count, res, err := OrderedSRV("kerberos", "tcp", "test.gokrb5")
		if err != nil {
			t.Errorf("error resolving SRV DNS records: %v", err)
		}
		expected := []string{
			"kdc.test.gokrb5:88",
			"kdc1a.test.gokrb5:88",
			"kdc2a.test.gokrb5:88",
			"kdc1b.test.gokrb5:88",
			"kdc2b.test.gokrb5:88",
		}
		assert.Equal(t, len(expected), count, "Number of SRV records not as expected: %v", res)
		assert.Equal(t, count, len(res), "Map size does not match: %v", res)
		for _, s := range expected {
			var found bool
			for _, v := range res {
				srvStr := strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
				if s == srvStr {
					found = true
					break
				}
			}
			assert.True(t, found, "Record %s not found in results", s)
		}
	}
}
