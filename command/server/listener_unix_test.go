// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/internalshared/configutil"
)

func TestUnixListener(t *testing.T) {
	ln, _, _, err := unixListenerFactory(&configutil.Listener{
		Address: filepath.Join(t.TempDir(), "/vault.sock"),
	}, nil, nil, cli.NewMockUi())
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	connFn := func(lnReal net.Listener) (net.Conn, error) {
		return net.Dial("unix", ln.Addr().String())
	}

	testListenerImpl(t, ln, connFn, "", 0, "", false)
}
