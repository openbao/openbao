// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/assert"
)

func TestConnectCAQuery_Fetch(t *testing.T) {
	d := NewConnectCAQuery()
	raw, _, err := d.Fetch(testClients, nil)
	assert.NoError(t, err)
	act := raw.([]*api.CARoot)
	if assert.Len(t, act, 1) {
		ca := act[0]
		// Root CA name can vary
		valid := []string{"Consul CA Root Cert", "Consul CA Primary Cert"}
		assert.Contains(t, valid, ca.Name)
		assert.True(t, ca.Active)
		assert.NotEmpty(t, ca.RootCertPEM)
	}
}
