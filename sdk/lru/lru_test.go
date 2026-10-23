package lru

import (
	"fmt"
	"testing"
)

func TestLRU(t *testing.T) {
	// Test creation with valid size
	lru, err := NewLRU[string, int](10)
	if err != nil {
		t.Fatalf("Failed to create LRU: %v", err)
	}
	if lru.Size() != 10 {
		t.Errorf("Expected size 10, got %d", lru.Size())
	}

	// Test creation with invalid size
	_, err = NewLRU[string, int](-1)
	if err == nil {
		t.Error("Expected error for negative size, got nil")
	}

	// Test basic operations
	t.Run("Basic Operations", func(t *testing.T) {
		lru, _ := NewLRU[string, int](5)

		// Test Store and Load
		lru.Add("key1", 1)
		val, ok := lru.Get("key1")
		if !ok || val != 1 {
			t.Errorf("Expected (1, true), got (%d, %t)", val, ok)
		}

		// Test missing key
		_, ok = lru.Get("missing")
		if ok {
			t.Error("Expected missing key to return ok=false")
		}

		// Test Delete
		lru.Add("key2", 2)
		lru.Delete("key2")
		_, ok = lru.Get("key2")
		if ok {
			t.Error("Expected key to be deleted")
		}

		// Test Purge
		lru.Add("key3", 3)
		lru.Add("key4", 4)
		lru.Add("key5", 5)
		lru.Purge() // Clear the cache
		for i := 3; i <= 5; i++ {
			_, ok := lru.Get(fmt.Sprintf("key%d", i))
			if ok {
				t.Errorf("Expected key%d to be purged", i)
			}
		}
	})

	t.Run("Overwrite", func(t *testing.T) {
		lru, _ := NewLRU[string, int](3)
		lru.Add("key1", 1)
		lru.Add("key1", 2)
		val, ok := lru.Get("key1")
		if !ok || val != 2 {
			t.Errorf("Expected (2, true), got (%d, %t)", val, ok)
		}
	})

	// Test eviction
	t.Run("Eviction", func(t *testing.T) {
		lru, _ := NewLRU[string, int](3)

		// Fill the cache
		lru.Add("key1", 1)
		lru.Add("key2", 2)
		lru.Add("key3", 3)

		// Add one more to trigger eviction
		lru.Add("key4", 4)

		// One of the keys should be evicted (likely key1 with TwoQueueCache)
		// But we can't guarantee which one, so just check total keys
		var count int
		for _, k := range []string{"key1", "key2", "key3", "key4"} {
			if _, ok := lru.Get(k); ok {
				count++
			}
		}

		if count != 3 {
			t.Errorf("Expected 3 keys in cache, found %d", count)
		}
	})

	// Test with different types
	t.Run("Different Types", func(t *testing.T) {
		lru, _ := NewLRU[int, string](5)
		lru.Add(1, "one")
		lru.Add(2, "two")

		val, ok := lru.Get(1)
		if !ok || val != "one" {
			t.Errorf("Expected (\"one\", true), got (%s, %t)", val, ok)
		}
	})
}
