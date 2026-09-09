// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import "crypto/subtle"

// containsKeyShare compares every share so a match does not reveal its position.
// For fixed share lengths, the comparison work is independent of the contents.
func containsKeyShare(shares [][]byte, key []byte) bool {
	found := 0
	for _, share := range shares {
		found |= subtle.ConstantTimeCompare(share, key)
	}
	return found == 1
}
