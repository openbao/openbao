// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

// mountEntrySysView creates a logical.SystemView from global and
// mount-specific entries; because this should be called when setting
// up a mountEntry, it doesn't check to ensure that me is not nil
func (c *Core) mountEntrySysView(entry *MountEntry) extendedSystemView {
	esi := extendedSystemViewImpl{
		dynamicSystemView{
			core:       c,
			mountEntry: entry,
		},
	}

	// Due to complexity in the ACME interface, only return it when we
	// are a PKI plugin that needs it.
	if entry.Type != "pki" {
		return esi
	}

	return esi
}
