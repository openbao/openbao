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

func TestUnixListener_SocketModeOnly(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "vault.sock")

	ln, _, _, err := unixListenerFactory(&configutil.Listener{
		Address:    sockPath,
		SocketMode: "0600",
	}, nil, cli.NewMockUi())
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	defer ln.Close()

	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat failed: %s", err)
	}

	// os.FileMode includes the socket type bit; mask to permission bits only
	got := fi.Mode().Perm()
	want := os.FileMode(0600)
	if got != want {
		t.Errorf("socket mode = %04o, want %04o", got, want)
	}
}
