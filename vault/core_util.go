// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/physical"
)

func coreInit(c *Core, conf *CoreConfig) error {
	phys := conf.Physical
	_, txnOK := phys.(physical.Transactional)
	sealUnwrapperLogger := conf.Logger.Named("storage.sealunwrapper")
	c.allLoggers = append(c.allLoggers, sealUnwrapperLogger)
	c.sealUnwrapper = NewSealUnwrapper(phys, sealUnwrapperLogger)
	// Wrap the physical backend in a cache layer if enabled
	cacheLogger := c.baseLogger.Named("storage.cache")
	c.allLoggers = append(c.allLoggers, cacheLogger)
	if txnOK {
		c.physical = physical.NewTransactionalCache(c.sealUnwrapper, conf.CacheSize, cacheLogger, c.MetricSink().Sink)
	} else {
		c.physical = physical.NewCache(c.sealUnwrapper, conf.CacheSize, cacheLogger, c.MetricSink().Sink)
	}
	c.physicalCache = c.physical.(physical.ToggleablePurgemonster)

	// Wrap in encoding checks
	if !conf.DisableKeyEncodingChecks {
		c.physical = physical.NewStorageEncoding(c.physical)
	}

	return nil
}

func (c *Core) barrierViewForNamespace(namespaceId string) (*BarrierView, error) {
	if namespaceId != namespace.RootNamespaceID {
		return nil, fmt.Errorf("failed to find barrier view for non-root namespace")
	}

	return c.systemBarrierView, nil
}

func preSealPhysical(c *Core) {
	switch c.sealUnwrapper.(type) {
	case *sealUnwrapper:
		c.sealUnwrapper.(*sealUnwrapper).stopUnwraps()
	case *transactionalSealUnwrapper:
		c.sealUnwrapper.(*transactionalSealUnwrapper).stopUnwraps()
	}

	// Purge the cache
	c.physicalCache.SetEnabled(false)
	c.physicalCache.Purge(context.Background())
}

func postUnsealPhysical(c *Core) error {
	switch c.sealUnwrapper.(type) {
	case *sealUnwrapper:
		c.sealUnwrapper.(*sealUnwrapper).runUnwraps()
	case *transactionalSealUnwrapper:
		c.sealUnwrapper.(*transactionalSealUnwrapper).runUnwraps()
	}
	return nil
}

func (c *Core) collectNamespaces() []*namespace.Namespace {
	return []*namespace.Namespace{
		namespace.RootNamespace,
	}
}
