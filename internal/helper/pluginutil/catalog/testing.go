// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package catalog

import "testing"

// TestKillClient kills a client's backing process, to simulate a client crash
// in tests.
func TestKillClient(t testing.TB, c *Client) {
	c.process.Kill()
}
