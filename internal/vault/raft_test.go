// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureAddrPort(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1":      "127.0.0.1:8200",
		"127.0.0.1:8300": "127.0.0.1:8300",

		"::1":        "[::1]:8200",
		"[::1]":      "[::1]:8200",
		"[::1]:8300": "[::1]:8300",

		"d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8":        "[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]:8200",
		"[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]":      "[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]:8200",
		"[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]:8300": "[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]:8300",

		"node1.example.com":       "node1.example.com:8200",
		"node1.example.com:8300":  "node1.example.com:8300",
		"node1.example.com.":      "node1.example.com.:8200",
		"node1.example.com.:8300": "node1.example.com.:8300",
	} {
		t.Run(addr, func(t *testing.T) {
			require.Equal(t, want, ensureAddrPort(addr, 8200))
		})
	}
}
