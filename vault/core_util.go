// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical"
)

func coreInit(c *Core, conf *CoreConfig) error {
	phys := conf.Physical

	// Set our invalidation hook.
	invalidating, ok := phys.(physical.CacheInvalidationBackend)
	if !ok && !conf.DisableCache && conf.HAPhysical != nil && conf.HAPhysical.HAEnabled() {
		// Disabling caching on HA-enabled backends.
		conf.DisableCache = true
		c.cachingDisabled = true
	} else if ok {
		c.logger.Trace("hooking invalidation")
		invalidating.HookInvalidate(c.Invalidate)
	}

	confirming, ok := phys.(physical.HAGRPCInvalidateConfirm)
	if ok {
		confirming.HookConfirmInvalidate(c.InvalidateConfirm)
	}

	// Wrap the physical backend in a cache layer if enabled
	cacheLogger := c.baseLogger.Named("storage.cache")
	c.allLoggers = append(c.allLoggers, cacheLogger)
	c.physical = physical.NewCache(phys, conf.CacheSize, cacheLogger, c.MetricSink().Sink)
	c.physicalCache = c.physical.(physical.ToggleablePurgemonster)

	// Wrap in encoding checks
	if !conf.DisableKeyEncodingChecks {
		c.physical = physical.NewStorageEncoding(c.physical)
	}

	return nil
}

func preSealPhysical(c *Core) {
	// Purge the cache
	c.physicalCache.SetEnabled(false)
	c.physicalCache.Purge(context.Background())
}

func postUnsealPhysical(c *Core) error {
	return nil
}

func (c *Core) notifyPhysicalLeadership(active bool) {
	if notifiable, ok := c.ha.(physical.LeadershipChangedBackend); ok {
		notifiable.LeadershipChange(active)
	}
}

func (c *Core) getActivePhysicalCheckpoint(ctx context.Context) (string, error) {
	if checkpointable, ok := c.ha.(physical.HALeaderSync); ok {
		return checkpointable.GetHACheckpoint(ctx)
	}

	return "", nil
}

func (c *Core) getStandbyPhysicalCheckpoint(ctx context.Context) (string, error) {
	if checkpointable, ok := c.ha.(physical.HALeaderSync); ok {
		return checkpointable.GetCurrentHACheckpoint(ctx)
	}

	return "", nil
}

func (c *Core) waitPhysicalCheckpoint(ctx context.Context, checkpoint string) error {
	if checkpointable, ok := c.ha.(physical.HALeaderSync); ok {
		return checkpointable.WaitHACheckpoint(ctx, checkpoint)
	}

	return nil
}

func (c *Core) notifyPhysicalStandby(id string, checkpoint string, expiry time.Time) {
	if notifiable, ok := c.ha.(physical.LeadershipChangedBackend); ok {
		notifiable.StandbyHeartbeat(id, checkpoint, expiry)
	}
}

func (c *Core) InvalidateConfirm(identifier string) {
	c.requestForwardingConnectionLock.RLock()
	defer c.requestForwardingConnectionLock.RUnlock()

	if c.rpcForwardingClient == nil {
		c.logger.Trace("no forwarding client when confirming invalidation", "identifier", identifier)
		return
	}

	if err := c.rpcForwardingClient.ConfirmInvalidate(identifier); err != nil {
		c.logger.Error("error confirming invalidation; initiating preseal", "error", err)
		return
	}
}
