// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type hostPort struct {
	host string
	port uint16
}

func TestEnsureHostPort(t *testing.T) {
	for addr, want := range map[string]hostPort{
		"127.0.0.1":      {host: "127.0.0.1", port: 8200},
		"127.0.0.1:8300": {host: "127.0.0.1", port: 8300},

		"::1":        {host: "::1", port: 8200},
		"[::1]":      {host: "::1", port: 8200},
		"[::1]:8300": {host: "::1", port: 8300},

		"d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8":        {host: "d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8", port: 8200},
		"[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]":      {host: "d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8", port: 8200},
		"[d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8]:8300": {host: "d47d:8266:5b5b:7030:4831:b60f:56d3:bfb8", port: 8300},

		"node1.example.com":       {host: "node1.example.com", port: 8200},
		"node1.example.com:8300":  {host: "node1.example.com", port: 8300},
		"node1.example.com.":      {host: "node1.example.com.", port: 8200},
		"node1.example.com.:8300": {host: "node1.example.com.", port: 8300},
	} {
		t.Run(addr, func(t *testing.T) {
			host, port, err := ensureHostPort(addr, 8200)
			require.NoError(t, err)
			require.Equal(t, want, hostPort{host: host, port: port})
		})
	}
}
