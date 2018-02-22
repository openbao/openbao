package dnsutils

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestOrderSRV(t *testing.T) {
	srv11 := net.SRV{
		Target:   "t11",
		Port:     1234,
		Priority: 1,
		Weight:   100,
	}
	srv12 := net.SRV{
		Target:   "t12",
		Port:     1234,
		Priority: 1,
		Weight:   100,
	}
	srv13 := net.SRV{
		Target:   "t13",
		Port:     1234,
		Priority: 1,
		Weight:   20,
	}
	srv21 := net.SRV{
		Target:   "t21",
		Port:     1234,
		Priority: 2,
		Weight:   1,
	}

	addrs := []*net.SRV{
		&srv11, &srv21, &srv12, &srv13,
	}
	count, orderedSRV := orderSRV(addrs)
	assert.Equal(t, len(addrs), count, "Index not the expected size")
	assert.Equal(t, len(addrs), len(orderedSRV), "orderedSRV not the expected size")
	assert.Equal(t, uint16(2), orderedSRV[4].Priority, "Priority order not as expected")
}
