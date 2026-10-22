// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
)

// TestIsLoopback verifies the loopback classification of bind addresses.
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		addr    string
		looptap bool
		name    string
	}{
		{"127.0.0.1:8200", true, "v4 loopback specific"},
		{"[::1]:8200", true, "v6 loopback specific (bracketed)"},
		{"0.0.0.0:8200", false, "v4 any"},
		{":::8200", false, "v6 any"},
		{"10.0.0.1:8200", false, "private v4 specific"},
		{"192.168.1.1:8200", false, "private v4 lan"},
		{"example.com:8200", false, "hostname (non-loopback)"},
		{"127.0.0.2:8200", true, "v4 loopback range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopback(tc.addr); got != tc.looptap {
				t.Fatalf("isLoopback(%q) = %v, want %v", tc.addr, got, tc.looptap)
			}
		})
	}
}

// TestWarnInsecureListener verifies the WARN classification decision for
// listener configs (TLS disabled + non-loopback => warn).
func TestWarnInsecureListener(t *testing.T) {
	cases := []struct {
		name     string
		ln       *configutil.Listener
		expectW  bool
	}{
		{"tls-disabled + 0.0.0.0 => warn", &configutil.Listener{Type: "tcp", Address: "0.0.0.0:8200", TLSDisable: true}, true},
		{"tls-disabled + :: => warn", &configutil.Listener{Type: "tcp", Address: ":::8200", TLSDisable: true}, true},
		{"tls-disabled + private IP => warn", &configutil.Listener{Type: "tcp", Address: "192.168.1.5:8200", TLSDisable: true}, true},
		{"tls-disabled + 127.0.0.1 => no warn", &configutil.Listener{Type: "tcp", Address: "127.0.0.1:8200", TLSDisable: true}, false},
		{"tls-enabled + 0.0.0.0 => no warn", &configutil.Listener{Type: "tcp", Address: "0.0.0.0:443", TLSDisable: false}, false},
		{"tls-enabled + 127.0.0.1 => no warn", &configutil.Listener{Type: "tcp", Address: "127.0.0.1:8200", TLSDisable: false}, false},
		{"unix socket => no warn", &configutil.Listener{Type: "unix", Address: "/var/run/openbao.sock", TLSDisable: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ListenerInsecure(tc.ln); got != tc.expectW {
				t.Fatalf("listenerInsecure(%+v) = %v, want %v", tc.ln, got, tc.expectW)
			}
		})
	}
}
