// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
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
	path := filepath.Join(t.TempDir(), "mode-only.sock")
	ln, _, _, err := unixListenerFactory(&configutil.Listener{
		Address:    path,
		SocketMode: "660",
	}, nil, cli.NewMockUi())
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("mode-only factory: got %o, want 660", fi.Mode().Perm())
	}
}
