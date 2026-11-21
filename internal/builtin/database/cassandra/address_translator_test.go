// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cassandra

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPortAddressTranslator_NoPort(t *testing.T) {
	require.Nil(t, newPortAddressTranslator(0))
}

func TestNewPortAddressTranslator_ConfiguredPortWins(t *testing.T) {
	tr := newPortAddressTranslator(9142)
	require.NotNil(t, tr)

	for _, ip := range []string{"10.1.2.3", "fd00::1"} {
		for _, advertised := range []int{9042, 7000, 0} {
			in := net.ParseIP(ip)
			gotIP, gotPort := tr.Translate(in, advertised)
			require.True(t, in.Equal(gotIP), "address must be unchanged")
			require.Equal(t, 9142, gotPort)
		}
	}
}

func TestNewClusterConfig_AddressTranslator(t *testing.T) {
	t.Run("port unset leaves translator nil", func(t *testing.T) {
		c := &cassandraConnectionProducer{Hosts: "10.1.2.3"}
		cfg := c.newClusterConfig()
		require.Nil(t, cfg.AddressTranslator)
		require.Equal(t, 9042, cfg.Port)
	})

	t.Run("port set installs translator", func(t *testing.T) {
		c := &cassandraConnectionProducer{Hosts: "10.1.2.3", Port: 9142}
		cfg := c.newClusterConfig()
		require.NotNil(t, cfg.AddressTranslator)
		require.Equal(t, 9142, cfg.Port)
	})
}
