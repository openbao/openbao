// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package systemd

import (
	"net"
	"os"
)

const (
	Ready     = "READY=1"
	Stopping  = "STOPPING=1"
	Reloading = "RELOADING=1"
)

// Notify implements systemd's NOTIFY_SOCKET protocol.
// See also: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
func Notify(state string) (bool, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return false, nil
	}

	addr := &net.UnixAddr{
		Name: socket,
		Net:  "unixgram",
	}
	conn, err := net.DialUnix(addr.Net, nil, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close() //nolint:errcheck

	if _, err = conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}
