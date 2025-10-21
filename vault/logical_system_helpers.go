// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// tuneMount is used to set config on a mount point
func (b *SystemBackend) tuneMountTTLs(ctx context.Context, path string, me *MountEntry, newDefault, newMax time.Duration) error {
	zero := time.Duration(0)

	switch {
	case newDefault == zero && newMax == zero:
		// No checks needed

	case newDefault == zero && newMax != zero:
		// No default/max conflict, no checks needed

	case newDefault != zero && newMax == zero:
		// No default/max conflict, no checks needed

	case newDefault != zero && newMax != zero:
		if newMax < newDefault {
			return fmt.Errorf("backend max lease TTL of %d would be less than backend default lease TTL of %d", int(newMax.Seconds()), int(newDefault.Seconds()))
		}
	}

	origMax := me.Config.MaxLeaseTTL
	origDefault := me.Config.DefaultLeaseTTL

	me.Config.MaxLeaseTTL = newMax
	me.Config.DefaultLeaseTTL = newDefault

	// Update the mount table
	var err error
	switch {
	case strings.HasPrefix(path, credentialRoutePrefix):
		err = b.Core.persistAuth(ctx, nil, b.Core.auth, &me.Local, me.UUID)
	default:
		err = b.Core.persistMounts(ctx, nil, b.Core.mounts, &me.Local, me.UUID)
	}
	if err != nil {
		me.Config.MaxLeaseTTL = origMax
		me.Config.DefaultLeaseTTL = origDefault
		return errors.New("failed to update mount table, rolling back TTL changes")
	}
	if b.Core.logger.IsInfo() {
		b.Core.logger.Info("mount tuning of leases successful", "path", path)
	}

	return nil
}
