// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	_ "crypto/sha512"
	"fmt"
	"io"
	"net"

	// We must import sha512 so that it registers with the runtime so that
	// certificates that use it can be parsed.

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/proxyutil"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/internalshared/listenerutil"
)

// ListenerFactory is the factory function to create a listener.
type ListenerFactory func(*configutil.Listener, hclog.Logger, io.Writer, cli.Ui) (net.Listener, map[string]string, listenerutil.ReloadableCertGetter, error)

// BuiltinListeners is the list of built-in listener types.
var BuiltinListeners = map[string]ListenerFactory{
	"tcp":  tcpListenerFactory,
	"unix": unixListenerFactory,
}

// NewListener creates a new listener of the given type with the given
// configuration. The type is looked up in the BuiltinListeners map.
func NewListener(l *configutil.Listener, logger hclog.Logger, logGate io.Writer, ui cli.Ui) (net.Listener, map[string]string, listenerutil.ReloadableCertGetter, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	return f(l, logger, logGate, ui)
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
