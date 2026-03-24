// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/helper/configutil"
)

func TestUnixListener(t *testing.T) {
	ln, _, _, err := unixListenerFactory(&configutil.Listener{
		Address: filepath.Join(t.TempDir(), "/vault.sock"),
	}, nil, cli.NewMockUi())
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	connFn := func(lnReal net.Listener) (net.Conn, error) {
		return net.Dial("unix", ln.Addr().String())
	}

	testListenerImpl(t, ln, connFn, "", 0, "", false)
}

func TestUnixListenerModeOnly(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "vault.sock")
	ln, _, _, err := unixListenerFactory(&configutil.Listener{
		Address:    addr,
		SocketMode: "644",
	}, nil, cli.NewMockUi())
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ln.Close()

	fi, err := os.Stat(addr)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("expected permissions %o, got %o", 0o644, fi.Mode().Perm())
	}
}
