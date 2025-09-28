// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
)

const (
	// defaultOrder is the default maximum number of children per B+ tree node
	defaultOrder = 32
	// defaultTreeID is the default identifier for a B+ tree when no specific ID is provided
	defaultTreeID string = "default"

	// bptreeConfigVersion is the current version of the BPlusTreeConfig schema
	bptreeConfigVersion1 = 1
	// latestBPlusTreeConfigVersion is the latest supported version of the BPlusTreeConfig schema
	latestBPlusTreeConfigVersion = bptreeConfigVersion1
)

// BPlusTreeConfig holds configuration options for the B+ tree.
// This struct serves both as runtime configuration and persistent metadata.
type BPlusTreeConfig struct {
	TreeID  string `json:"tree_id"` // Tree name/identifier for multi-tree storage
	Order   int    `json:"order"`   // Maximum number of children per node
	Version int    `json:"version"` // Configuration version for future schema evolution
}

func NewDefaultBPlusTreeConfig() *BPlusTreeConfig {
	return &BPlusTreeConfig{
		TreeID:  defaultTreeID,
		Order:   defaultOrder,
		Version: latestBPlusTreeConfigVersion,
	}
}

// NewBPlusTreeConfig creates a new BPlusTreeConfig with functional options
func NewBPlusTreeConfig(opts ...TreeOption) (*BPlusTreeConfig, error) {
	// Start with defaults
	config := NewDefaultBPlusTreeConfig()

	// Apply options
	ApplyTreeOptions(config, opts...)

	// Validate the final configuration
	if err := ValidateTreeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid tree configuration: %w", err)
	}

	return config, nil
}

func (c *BPlusTreeConfig) contextWithTreeID(ctx context.Context) context.Context {
	if c == nil || c.TreeID == "" {
		return ctx // No tree ID to add
	}

	return withTreeID(ctx, c.TreeID)
}

// TreeOption is a functional option for configuring BPlusTreeConfig
type TreeOption func(*BPlusTreeConfig)

// WithTreeID sets the tree identifier
func WithTreeID(treeID string) TreeOption {
	return func(c *BPlusTreeConfig) {
		c.TreeID = treeID
	}
}

// WithOrder sets the maximum number of children per node
func WithOrder(order int) TreeOption {
	return func(c *BPlusTreeConfig) {
		c.Order = order
	}
}

// WithVersion sets the configuration version
func WithVersion(version int) TreeOption {
	return func(c *BPlusTreeConfig) {
		c.Version = version
	}
}

// ValidateTreeConfig validates the BPlusTreeConfig
func ValidateTreeConfig(cfg *BPlusTreeConfig) error {
	if cfg == nil {
		return fmt.Errorf("BPlusTreeConfig cannot be nil")
	}

	if cfg.Order < 3 {
		return fmt.Errorf("order must be at least 3, got %d", cfg.Order)
	}

	return nil
}

// ApplyTreeOptions applies multiple TreeOptions to a BPlusTreeConfig
func ApplyTreeOptions(config *BPlusTreeConfig, opts ...TreeOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}
}
