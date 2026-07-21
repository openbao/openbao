// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/stretchr/testify/require"
)

const reloadFixturesDir = "../../server/test-fixtures/reload/"

func TestStartListener_TLSAutoReloadServesRotatedCertWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	installCertPair(t, "foo", certPath, keyPath)

	bundle, err := StartListener(&configutil.Listener{
		Type:                  "tcp",
		Address:               "127.0.0.1:0",
		TLSCertFile:           certPath,
		TLSKeyFile:            keyPath,
		TLSAutoReload:         true,
		TLSAutoReloadInterval: 50 * time.Millisecond,
	}, hclog.NewNullLogger())
	require.NoError(t, err)

	ln := bundle.Listener
	t.Cleanup(func() { _ = ln.Close() })
	go serveTLSHandshakes(ln)

	installCertPair(t, "bar", certPath, keyPath)

	require.Eventually(t, func() bool {
		certName, err := servedCertName(ln.Addr().String())
		return err == nil && certName == "bar.example.com"
	}, 3*time.Second, 50*time.Millisecond, "cert was not auto-reloaded")
}

func servedCertName(addr string) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
}

func serveTLSHandshakes(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}()
	}
}

func installCertPair(t *testing.T, fixtureName, certPath, keyPath string) {
	t.Helper()
	copyFile(t, reloadFixturesDir+"reload_"+fixtureName+".pem", certPath)
	copyFile(t, reloadFixturesDir+"reload_"+fixtureName+".key", keyPath)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	content, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst+".tmp", content, 0o600))
	require.NoError(t, os.Rename(dst+".tmp", dst))
}
