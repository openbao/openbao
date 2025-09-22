package bptree

import (
	"encoding/json"
	"errors"
)

// NOTE (gabrielopesantos): This is probably not needed (standard JSON serialization is fine for now)
// NodeSerializer defines how to serialize and deserialize nodes
type NodeSerializer interface {
	Serialize(node *Node) ([]byte, error)
	Deserialize(data []byte) (*Node, error)
}

// JSONSerializer is a simple JSON-based serializer for nodes
type JSONSerializer struct{}

// Serialize converts a node to JSON
func (s *JSONSerializer) Serialize(node *Node) ([]byte, error) {
	return json.Marshal(node)
}

// Deserialize converts JSON to a node
func (s *JSONSerializer) Deserialize(data []byte) (*Node, error) {
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

type StorageConfig struct {
	// NodeSerializer defines how nodes are serialized/deserialized
	NodeSerializer NodeSerializer

	// Enable or disable caching at the storage layer
	CachingEnabled bool
	// Cache size for node caching (if caching is enabled)
	CacheSize int

	// Enable or disable built-in write buffering at the storage layer
	BufferingEnabled bool
}

// NewStorageConfig creates a default storage config with optional overrides
// for non transactional storage.
func NewStorageConfig(opts ...StorageOption) *StorageConfig {
	cfg := &StorageConfig{
		NodeSerializer:   &JSONSerializer{}, // Default to JSON serializer
		CachingEnabled:   true,              // Enable caching by default
		CacheSize:        1000,              // Default cache size
		BufferingEnabled: false,             // Enable buffering by default
	}

	// Apply options
	ApplyStorageOptions(cfg, opts...)

	return cfg
}

// NewTransactionalStorageConfig creates a default storage config with optional
// overrides for transactional storage.
func NewTransactionalStorageConfig(opts ...StorageOption) *StorageConfig {
	cfg := &StorageConfig{
		NodeSerializer:   &JSONSerializer{}, // Default to JSON serializer
		CachingEnabled:   true,              // Enable caching by default
		CacheSize:        100,               // Smaller cache for transactional storage
		BufferingEnabled: true,              // Enable buffering by default
	}

	// Apply options
	ApplyStorageOptions(cfg, opts...)

	return cfg
}

func ValidateStorageConfig(cfg *StorageConfig) error {
	if cfg.NodeSerializer == nil {
		return errors.New("NodeSerializer cannot be nil")
	}
	if cfg.CachingEnabled && cfg.CacheSize <= 0 {
		return errors.New("CacheSize must be positive when caching is enabled")
	}

	return nil
}

// Write an options pattern for configuring storage
type StorageOption func(*StorageConfig)

// WithNodeSerializer sets a custom node serializer
func WithNodeSerializer(serializer NodeSerializer) StorageOption {
	return func(cfg *StorageConfig) {
		cfg.NodeSerializer = serializer
	}
}

// WithCachingEnabled enables or disables caching
func WithCachingEnabled(enabled bool) StorageOption {
	return func(cfg *StorageConfig) {
		cfg.CachingEnabled = enabled
	}
}

// WithCacheSize sets the cache size
func WithCacheSize(size int) StorageOption {
	return func(cfg *StorageConfig) {
		cfg.CacheSize = size
	}
}

// WithBufferingEnabled enables or disables built-in write buffering
func WithBufferingEnabled(enabled bool) StorageOption {
	return func(cfg *StorageConfig) {
		cfg.BufferingEnabled = enabled
	}
}

// ApplyStorageOptions applies given options to the storage config
func ApplyStorageOptions(cfg *StorageConfig, opts ...StorageOption) {
	for _, opt := range opts {
		opt(cfg)
	}
}
