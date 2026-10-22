// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	_ "crypto/sha512"
	"fmt"
	"net"

	// We must import sha512 so that it registers with the runtime so that
	// certificates that use it can be parsed.

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/listenerutil"
	"github.com/openbao/openbao/v2/internal/helper/proxyutil"
)

// ListenerFactory is the factory function to create a listener.
type ListenerFactory func(*configutil.Listener, hclog.Logger, cli.Ui) (net.Listener, map[string]string, listenerutil.ReloadableCertGetter, error)

// BuiltinListeners is the list of built-in listener types.
var BuiltinListeners = map[string]ListenerFactory{
	"tcp":  tcpListenerFactory,
	"unix": unixListenerFactory,
}

// NewListener creates a new listener of the given type with the given
// configuration. The type is looked up in the BuiltinListeners map.
func NewListener(l *configutil.Listener, logger hclog.Logger, ui cli.Ui) (net.Listener, map[string]string, listenerutil.ReloadableCertGetter, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	return f(l, logger, ui)
}

func listenerWrapProxy(ln net.Listener, l *configutil.Listener) (net.Listener, error) {
	behavior := l.ProxyProtocolBehavior
	if behavior == "" {
		return ln, nil
	}

	proxyProtoConfig := &proxyutil.ProxyProtoConfig{
		Behavior:        behavior,
		AuthorizedAddrs: l.ProxyProtocolAuthorizedAddrs,
	}

	newLn, err := proxyutil.WrapInProxyProto(ln, proxyProtoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed configuring PROXY protocol wrapper: %w", err)
	}

	return newLn, nil
}

// isLoopback reports whether the host portion of a listener bind address
// refers to the loopback interface. The address is a "host:port" string.
// Any hostname that is not a loopback IP literal (127.x, ::1) is treated as
// non-loopback, since it may resolve to an externally reachable address.
func isLoopback(addr string) bool {
	// Handle "host:port" for both IPv4 and IPv6. For IPv6, the host part is
	// bracketed (e.g. [::1]:8200); SplitHostPort strips the brackets.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a host:port form (e.g. a unix socket path or a bare address);
		// treat as non-loopback for safety.
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// ListenerInsecure reports whether a listener configuration should trigger a
// startup warning: plaintext (TLS disabled) bound to a non-loopback address.
// Unix sockets are exempt.
func ListenerInsecure(l *configutil.Listener) bool {
	if l == nil || l.Type != "tcp" || !l.TLSDisable {
		return false
	}
	return !isLoopback(l.Address)
}
