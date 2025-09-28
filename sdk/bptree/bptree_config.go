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

// TreeConfig holds configuration options for the B+ tree.
// This struct serves both as runtime configuration and persistent metadata.
type TreeConfig struct {
	TreeID  string `json:"tree_id"` // Tree name/identifier for multi-tree storage
	Order   int    `json:"order"`   // Maximum number of children per node
	Version int    `json:"version"` // Configuration version for future schema evolution
}

func NewDefaultTreeConfig() *TreeConfig {
	return &TreeConfig{
		TreeID:  defaultTreeID,
		Order:   defaultOrder,
		Version: latestBPlusTreeConfigVersion,
	}
}

// NewTreeConfig creates a new BPlusTreeConfig with functional options
func NewTreeConfig(opts ...TreeOption) (*TreeConfig, error) {
	// Start with defaults
	config := NewDefaultTreeConfig()

	// Apply options
	ApplyTreeOptions(config, opts...)

	// Validate the final configuration
	if err := ValidateTreeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid tree configuration: %w", err)
	}

	return config, nil
}

func (c *TreeConfig) contextWithTreeID(ctx context.Context) context.Context {
	if c == nil || c.TreeID == "" {
		return ctx // No tree ID to add
	}

	return withTreeID(ctx, c.TreeID)
}

// TreeOption is a functional option for configuring BPlusTreeConfig
type TreeOption func(*TreeConfig)

// WithTreeID sets the tree identifier
func WithTreeID(treeID string) TreeOption {
	return func(c *TreeConfig) {
		c.TreeID = treeID
	}
}

// WithOrder sets the maximum number of children per node
func WithOrder(order int) TreeOption {
	return func(c *TreeConfig) {
		c.Order = order
	}
}

// WithVersion sets the configuration version
func WithVersion(version int) TreeOption {
	return func(c *TreeConfig) {
		c.Version = version
	}
}

// ValidateTreeConfig validates the BPlusTreeConfig
func ValidateTreeConfig(cfg *TreeConfig) error {
	if cfg == nil {
		return fmt.Errorf("BPlusTreeConfig cannot be nil")
	}

	if cfg.TreeID == "" {
		return fmt.Errorf("TreeID cannot be empty")
	}

	if cfg.Order < 3 {
		return fmt.Errorf("order must be at least 3, got %d", cfg.Order)
	}

	return nil
}

// ApplyTreeOptions applies multiple TreeOptions to a BPlusTreeConfig
func ApplyTreeOptions(config *TreeConfig, opts ...TreeOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}
}
