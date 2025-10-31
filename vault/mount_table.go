// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"slices"
	"sort"
	"strings"

	metrics "github.com/armon/go-metrics"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
)

// MountTable is used to represent the internal mount table
type MountTable struct {
	Type    string        `json:"type"`
	Entries []*MountEntry `json:"entries"`
}

// shallowClone returns a copy of the mount table that
// keeps the MountEntry locations, so as not to invalidate
// other locations holding pointers. Care needs to be taken
// if modifying entries rather than modifying the table itself
func (t *MountTable) shallowClone() *MountTable {
	mt := &MountTable{
		Type:    t.Type,
		Entries: make([]*MountEntry, len(t.Entries)),
	}

	copy(mt.Entries, t.Entries)
	return mt
}

// setTaint is used to set the taint on given mount entry. Accepts either the mount
// entry's path or namespace + path, i.e. <ns-path>/secret/ or <ns-path>/token/
func (t *MountTable) setTaint(nsID, path string) *MountEntry {
	for _, entry := range t.Entries {
		if entry.Path == path && entry.Namespace().ID == nsID {
			entry.Tainted = true
			return entry
		}
	}

	return nil
}

// remove removes a given path entry; returns removed entry
func (t *MountTable) remove(ctx context.Context, path string) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var removed *MountEntry
	t.Entries = slices.DeleteFunc(t.Entries, func(me *MountEntry) bool {
		if me.Path == path && me.Namespace().ID == ns.ID {
			removed = me
			return true
		}
		return false
	})

	return removed, nil
}

func (t *MountTable) findByPath(ctx context.Context, path string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.Path == path })
}

func (t *MountTable) findByBackendUUID(ctx context.Context, backendUUID string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.BackendAwareUUID == backendUUID })
}

func (t *MountTable) findAllNamespaceMounts(ctx context.Context) ([]*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var mounts []*MountEntry
	for _, entry := range t.Entries {
		if entry.Namespace().ID == ns.ID {
			mounts = append(mounts, entry)
		}
	}

	return mounts, nil
}

// find returns back a mount entry using provided predicate
// also matching on the namespace provided in the context
func (t *MountTable) find(ctx context.Context, predicate func(*MountEntry) bool) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, entry := range t.Entries {
		if predicate(entry) && entry.Namespace().ID == ns.ID {
			return entry, nil
		}
	}

	//nolint:nilnil // fine as all callers account for both an error and entry not found.
	return nil, nil
}

// sortEntriesByPath sorts the entries in the table by path
// and returns the table; this is useful for tests
func (t *MountTable) sortEntriesByPath() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return t.Entries[i].Path < t.Entries[j].Path
	})
	return t
}

// sortEntriesByPathDepth sorts the entries in the table by
// "nesting" level of a namespace and returns the table;
// this is useful for tests
func (t *MountTable) sortEntriesByPathDepth() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return len(strings.Split(t.Entries[i].Namespace().Path+t.Entries[i].Path, "/")) < len(strings.Split(t.Entries[j].Namespace().Path+t.Entries[j].Path, "/"))
	})
	return t
}

// tableMetrics is responsible for setting gauge metrics for
// mount table storage sizes (in bytes) and mount table num
// entries. It does this via setGaugeWithLabels. It then
// saves these metrics in a cache for regular reporting in
// a loop, via AddGaugeLoopMetric.

// Note that the reported storage sizes are pre-encryption
// sizes. Currently barrier uses aes-gcm for encryption, which
// preserves plaintext size, adding a constant of 30 bytes of
// padding, which is negligible and subject to change, and thus
// not accounted for.
func (c *Core) tableMetrics(tableType string, isLocal bool, entryCount, compressedTableLen int) {
	if c.metricsHelper == nil {
		// do nothing if metrics are not initialized
		return
	}

	mountTableTypeLabelMap := map[string]metrics.Label{
		mountTableType:      {Name: "type", Value: "logical"},
		credentialTableType: {Name: "type", Value: "auth"},
		// we don't raport number of audit mounts, but adding it here for consistency
		auditTableType: {Name: "type", Value: "audit"},
	}

	localLabelMap := map[bool]metrics.Label{
		true:  {Name: "local", Value: "true"},
		false: {Name: "local", Value: "false"},
	}

	c.metricSink.SetGaugeWithLabels(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricSink.SetGaugeWithLabels(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})
}
