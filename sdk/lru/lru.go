package lru

import lru "github.com/hashicorp/golang-lru/v2"

type LRU[K comparable, V any] struct {
	size int
	lru  *lru.TwoQueueCache[K, V]
}

func NewLRU[K comparable, V any](size int) (*LRU[K, V], error) {
	lru, err := lru.New2Q[K, V](size)
	if err != nil {
		return nil, err
	}

	return &LRU[K, V]{lru: lru, size: size}, nil
}

// Delete removes a key from the cache.
func (c *LRU[K, V]) Delete(key K) {
	c.lru.Remove(key)
}

// Get returns the value for a key from the cache.
func (c *LRU[K, V]) Get(key K) (value V, ok bool) {
	return c.lru.Get(key)
}

// Add adds a key-value pair to the cache.
func (c *LRU[K, V]) Add(key K, value V) {
	c.lru.Add(key, value)
}

// Purge removes all items from the cache
func (c *LRU[K, V]) Purge() {
	c.lru.Purge()
}

func (c *LRU[K, V]) Size() int {
	return c.size
}
