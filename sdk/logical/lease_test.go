// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLeaseOptionsLeaseTotal(t *testing.T) {
	var l LeaseOptions
	l.TTL = 1 * time.Hour

	actual := l.LeaseTotal()
	require.Equal(t, l.TTL, actual)
}

func TestLeaseOptionsLeaseTotal_grace(t *testing.T) {
	var l LeaseOptions
	l.TTL = 1 * time.Hour

	actual := l.LeaseTotal()
	require.Equal(t, l.TTL, actual)
}

func TestLeaseOptionsLeaseTotal_negLease(t *testing.T) {
	var l LeaseOptions
	l.TTL = -1 * 1 * time.Hour

	actual := l.LeaseTotal()
	require.Equal(t, time.Duration(0), actual)
}

func TestLeaseOptionsExpirationTime(t *testing.T) {
	var l LeaseOptions
	l.TTL = 1 * time.Hour

	limit := time.Now().Add(time.Hour)
	exp := l.ExpirationTime()
	require.False(t, exp.Before(limit), "expiration time %s should not be before %s", exp, limit)
}

func TestLeaseOptionsExpirationTime_noLease(t *testing.T) {
	var l LeaseOptions
	require.True(t, l.ExpirationTime().IsZero(), "should be zero")
}
