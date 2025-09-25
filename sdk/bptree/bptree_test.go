// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestBPlusTreeBasicOperations(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	t.Run("EmptyTree", func(t *testing.T) {
		val, found, err := tree.Search(ctx, storage, "key1")
		require.NoError(t, err, "Should not error when getting from empty tree")
		require.False(t, found, "Should not find key in empty tree")
		require.Empty(t, val, "Value should be empty")
	})

	t.Run("InsertAndGet", func(t *testing.T) {
		// Insert a key
		err := tree.Insert(ctx, storage, "key1", "key1_value1")
		require.NoError(t, err, "Failed to insert key key1 with value key1_value1")
		err = tree.Insert(ctx, storage, "key1", "key1_value2")
		require.NoError(t, err, "Failed to insert key key1 with value key1_value2")

		// Insert other keys for testing
		err = tree.Insert(ctx, storage, "key2", "key2_value1")
		require.NoError(t, err, "Failed to insert key key2 with value key2_value1")

		err = tree.Insert(ctx, storage, "key3", "key3_value1")
		require.NoError(t, err, "Failed to insert key key3 with value key3_value1")

		// Get the key
		val, found, err := tree.Search(ctx, storage, "key1")
		require.NoError(t, err, "Error when getting key")
		require.True(t, found, "Should find inserted key")
		require.Equal(t, []string{"key1_value1", "key1_value2"}, val, "Retrieved value should match inserted value")
	})

	t.Run("SearchPrefix", func(t *testing.T) {
		// Search for a prefix
		result, err := tree.SearchPrefix(ctx, storage, "key")
		require.NoError(t, err, "Error when searching prefix")
		require.Len(t, result, 3, "Should find 3 keys with prefix 'key'")
		expectedKeys := []string{"key1", "key2", "key3"}
		expectedValues := [][]string{{"key1_value1", "key1_value2"}, {"key2_value1"}, {"key3_value1"}}
		for i, key := range expectedKeys {
			val, found := result[key]
			require.True(t, found, fmt.Sprintf("Should find key (%s) in prefix search", key))
			require.Equal(t, expectedValues[i], val, fmt.Sprintf("Values for key (%s) should match", key))
		}
	})

	t.Run("DeleteValue", func(t *testing.T) {
		// Delete a specific value
		deleted, err := tree.DeleteValue(ctx, storage, "key1", "key1_value1")
		require.NoError(t, err, "Failed to delete value key1_value1")
		require.True(t, deleted, "Should successfully delete value key1_value1")

		// Verify the value was deleted
		val, found, err := tree.Search(ctx, storage, "key1")
		require.NoError(t, err, "Error when getting key after deletion")
		require.True(t, found, "Should still find key after value deletion")
		require.Equal(t, []string{"key1_value2"}, val, "Retrieved value should not include deleted value")
	})

	t.Run("Delete", func(t *testing.T) {
		// Delete key
		deleted, err := tree.Delete(ctx, storage, "key1")
		require.NoError(t, err, "Failed to delete key")
		require.True(t, deleted, "Should successfully delete key")

		// Verify key was deleted
		val, found, err := tree.Search(ctx, storage, "key1")
		require.NoError(t, err, "Should not error when getting a deleted key")
		require.False(t, found, "Should not find deleted key")
		require.Empty(t, val, "Value should be empty after deletion")
	})

	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		deleted, err := tree.Delete(ctx, storage, "nonexistent")
		require.Nil(t, err, "Should not error when deleting non-existent key")
		require.False(t, deleted, "Should return false when deleting non-existent key")
	})
}

func TestBPlusTreeSearch(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	// Test search on empty tree
	val, found, err := tree.Search(ctx, storage, "nonexistent")
	require.NoError(t, err, "Search should not error on empty tree")
	require.False(t, found, "Should not find key in empty tree")
	require.Empty(t, val, "Values should be empty for non-existent key")

	// Insert some test data
	err = tree.Insert(ctx, storage, "apple", "fruit")
	require.NoError(t, err, "Insert should not error")
	err = tree.Insert(ctx, storage, "apple", "red")
	require.NoError(t, err, "Insert should not error")
	err = tree.Insert(ctx, storage, "banana", "yellow")
	require.NoError(t, err, "Insert should not error")

	// Test search for existing key with multiple values
	val, found, err = tree.Search(ctx, storage, "apple")
	require.NoError(t, err, "Search should not error")
	require.True(t, found, "Should find existing key 'apple'")
	require.Equal(t, []string{"fruit", "red"}, val, "Should return all values for key")

	// Test search for existing key with single value
	val, found, err = tree.Search(ctx, storage, "banana")
	require.NoError(t, err, "Search should not error")
	require.True(t, found, "Should find existing key 'banana'")
	require.Equal(t, []string{"yellow"}, val, "Should return single value for key")

	// Test search for non-existent key
	val, found, err = tree.Search(ctx, storage, "orange")
	require.NoError(t, err, "Search should not error for non-existent key")
	require.False(t, found, "Should not find non-existent key 'orange'")
	require.Empty(t, val, "Values should be empty for non-existent key")
}

// TestSearchPrefix tests the SearchPrefix functionality
func TestSearchPrefix(t *testing.T) {
	t.Run("BasicPrefixSearch", func(t *testing.T) {
		ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

		// Search in empty tree
		results, err := tree.SearchPrefix(ctx, storage, "any/prefix")
		require.NoError(t, err, "SearchPrefix should not fail on empty tree")
		require.Empty(t, results, "Empty tree should return empty results")

		// Empty prefix on empty tree
		results, err = tree.SearchPrefix(ctx, storage, "")
		require.NoError(t, err, "Empty prefix on empty tree should not fail")
		require.Empty(t, results, "Empty prefix should return empty results")

		// Insert keys with various prefixes
		keys := []string{
			"app/config",
			"app/config/db",
			"app/config/api",
			"app/secrets/api_key",
			"app/secrets/jwt_secret",
			"auth/users/alice",
			"auth/users/bob",
			"auth/roles/admin",
			"system/health",
			"system/version",
		}

		for _, key := range keys {
			err := tree.Insert(ctx, storage, key, keyValue(key))
			require.NoError(t, err, "Failed to insert (%s)", key)
		}

		// Test basic prefix search
		results, err = tree.SearchPrefix(ctx, storage, "app/")
		require.NoError(t, err, "SearchPrefix failed")
		require.Len(t, results, 5, "Should find 5 keys with 'app/' prefix")
		require.Contains(t, results, "app/config")
		require.Contains(t, results, "app/config/db")
		require.Contains(t, results, "app/config/api")
		require.Contains(t, results, "app/secrets/api_key")
		require.Contains(t, results, "app/secrets/jwt_secret")

		// Test more specific prefix
		results, err = tree.SearchPrefix(ctx, storage, "app/config/")
		require.NoError(t, err, "SearchPrefix failed")
		require.Len(t, results, 2, "Should find 2 keys with 'app/config/' prefix")
		require.Contains(t, results, "app/config/db")
		require.Contains(t, results, "app/config/api")

		// Test prefix with no matches
		results, err = tree.SearchPrefix(ctx, storage, "nonexistent/")
		require.NoError(t, err, "SearchPrefix should not fail on non-existent prefix")
		require.Empty(t, results, "Non-existent prefix should return empty results")

		// Test exact key as prefix
		results, err = tree.SearchPrefix(ctx, storage, "system")
		require.NoError(t, err, "SearchPrefix failed")
		require.Len(t, results, 2, "Should find keys starting with 'system'")
		require.Contains(t, results, "system/health")
		require.Contains(t, results, "system/version")

		// Test exact key match
		results, err = tree.SearchPrefix(ctx, storage, "app/config")
		require.NoError(t, err, "SearchPrefix failed")
		require.Len(t, results, 3, "Should find exact key match and keys with same prefix")
		require.Contains(t, results, "app/config")
		require.Contains(t, results, "app/config/db")
		require.Contains(t, results, "app/config/api")
	})

	t.Run("SpecialCharactersInPrefix", func(t *testing.T) {
		ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

		// Insert keys with special characters
		specialKeys := []string{
			"app/config-dev",
			"app/config_prod",
			"app/config.test",
			"app/config@staging",
			"app/config+backup",
			"app/config (legacy)",
			"app/config/with spaces",
			"app/config/with/unicode/🔑",
		}

		for _, key := range specialKeys {
			err := tree.Insert(ctx, storage, key, keyValue(key))
			require.NoError(t, err, "Failed to insert key with special chars: %s", key)
		}

		// Test prefix search with special characters
		results, err := tree.SearchPrefix(ctx, storage, "app/config-")
		require.NoError(t, err)
		require.Len(t, results, 1, "Should find 1 key with 'app/config-' prefix")
		require.Contains(t, results, "app/config-dev")

		results, err = tree.SearchPrefix(ctx, storage, "app/config_")
		require.NoError(t, err)
		require.Len(t, results, 1, "Should find 1 key with 'app/config_' prefix")
		require.Contains(t, results, "app/config_prod")

		// Test with Unicode
		results, err = tree.SearchPrefix(ctx, storage, "app/config/with/unicode/")
		require.NoError(t, err)
		require.Len(t, results, 1, "Should find 1 key with 'app/config/with/unicode/' prefix")
		require.Contains(t, results, "app/config/with/unicode/🔑")
	})

	t.Run("PrefixLongerThanAnyKey", func(t *testing.T) {
		ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

		// Insert short keys
		err := tree.Insert(ctx, storage, "a", "value1")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "ab", "value2")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "abc", "value3")
		require.NoError(t, err)

		// Search with prefix longer than any key
		results, err := tree.SearchPrefix(ctx, storage, "abcdefghijklmnop")
		require.NoError(t, err)
		require.Empty(t, results, "Prefix longer than any key should return empty results")
	})

	t.Run("CaseSensitivity", func(t *testing.T) {
		ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

		// Insert keys with different cases
		err := tree.Insert(ctx, storage, "App/Config", "mixed_case")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "app/config", "lower_case")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "APP/CONFIG", "upper_case")
		require.NoError(t, err)

		// Search should be case sensitive
		results, err := tree.SearchPrefix(ctx, storage, "app/")
		require.NoError(t, err)
		require.Len(t, results, 1, "Should find 1 key with 'app/' prefix")
		require.Contains(t, results, "app/config")

		results, err = tree.SearchPrefix(ctx, storage, "App/")
		require.NoError(t, err)
		require.Len(t, results, 1, "Should find 1 key with 'App/' prefix")
		require.Contains(t, results, "App/Config")
	})
}

// TestSearchPrefixWithNextIDTraversal tests that SearchPrefix properly uses NextID for traversal
func TestSearchPrefixWithNextIDTraversal(t *testing.T) {
	// Use very small order to force many splits and multiple leaf nodes
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	// Insert many keys to create multiple leaf nodes
	numKeys := 20
	for i := 1; i <= numKeys; i++ {
		key := fmt.Sprintf("key%02d", i) // key01, key02, ..., key20
		value := fmt.Sprintf("value%02d", i)
		err := tree.Insert(ctx, storage, key, value)
		require.NoError(t, err, "Failed to insert %s", key)
	}

	// Verify we have multiple leaves by checking NextID chain
	var leafCount int
	current, err := tree.findLeftmostLeaf(ctx, storage)
	require.NoError(t, err)

	for current != nil {
		leafCount++
		if current.NextID == "" {
			break
		}
		current, err = storage.GetNode(ctx, current.NextID)
		require.NoError(t, err)
	}

	require.GreaterOrEqual(t, leafCount, 2, "Should have created multiple leaves")

	// Test prefix search that spans multiple leaves
	results, err := tree.SearchPrefix(ctx, storage, "key")
	require.NoError(t, err)
	require.Len(t, results, numKeys, "Should find all keys with 'key' prefix")

	// Test more specific prefix that might span leaves
	results, err = tree.SearchPrefix(ctx, storage, "key1")
	require.NoError(t, err)
	expectedKey1Results := []string{"key10", "key11", "key12", "key13", "key14", "key15", "key16", "key17", "key18", "key19"}
	require.Len(t, results, len(expectedKey1Results), "Should find all 'key1*' matches")

	for _, expectedKey := range expectedKey1Results {
		require.Contains(t, results, expectedKey, "Should contain %s", expectedKey)
	}
}

// TestSearchPrefixComprehensive is a comprehensive test that demonstrates all functionality
func TestSearchPrefixComprehensive(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

	// Insert comprehensive test data
	testData := map[string]string{
		"app/config/db":       "database_config",
		"app/config/redis":    "redis_config",
		"app/secrets/api_key": "secret_api_key",
		"app/secrets/jwt":     "jwt_secret",
		"auth/users/alice":    "user_alice",
		"auth/users/bob":      "user_bob",
		"auth/roles/admin":    "admin_role",
		"auth/roles/user":     "user_role",
		"system/health":       "health_check",
		"system/version":      "version_info",
		"logs/app/error":      "error_logs",
		"logs/app/info":       "info_logs",
		"logs/system/debug":   "debug_logs",
	}

	for key, value := range testData {
		err := tree.Insert(ctx, storage, key, value)
		require.NoError(t, err, "Failed to insert %s", key)
	}

	// Test various prefix searches
	testCases := []struct {
		prefix           string
		expectedCount    int
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			prefix:        "app/",
			expectedCount: 4,
			shouldContain: []string{"app/config/db", "app/config/redis", "app/secrets/api_key", "app/secrets/jwt"},
		},
		{
			prefix:           "app/config/",
			expectedCount:    2,
			shouldContain:    []string{"app/config/db", "app/config/redis"},
			shouldNotContain: []string{"app/secrets/api_key"},
		},
		{
			prefix:        "auth/",
			expectedCount: 4,
			shouldContain: []string{"auth/users/alice", "auth/users/bob", "auth/roles/admin", "auth/roles/user"},
		},
		{
			prefix:        "logs/",
			expectedCount: 3,
			shouldContain: []string{"logs/app/error", "logs/app/info", "logs/system/debug"},
		},
		{
			prefix:        "nonexistent/",
			expectedCount: 0,
		},
		{
			prefix:        "",
			expectedCount: 0, // Empty prefix returns empty results
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Prefix_%s", tc.prefix), func(t *testing.T) {
			results, err := tree.SearchPrefix(ctx, storage, tc.prefix)
			require.NoError(t, err, "SearchPrefix failed for prefix: %s", tc.prefix)
			require.Len(t, results, tc.expectedCount, "Wrong result count for prefix: %s", tc.prefix)

			for _, key := range tc.shouldContain {
				require.Contains(t, results, key, "Should contain %s for prefix %s", key, tc.prefix)
				require.Equal(t, testData[key], results[key][0], "Wrong value for key %s", key)
			}

			for _, key := range tc.shouldNotContain {
				require.NotContains(t, results, key, "Should not contain %s for prefix %s", key, tc.prefix)
			}
		})
	}
}

func TestBPlusTreeInsert(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	// Test basic insert
	err := tree.Insert(ctx, storage, "key1", "value1")
	require.NoError(t, err, "Insert should not error")

	// Verify insert worked
	val, found, err := tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Search should not error")
	require.True(t, found, "Should find inserted key")
	require.Equal(t, []string{"value1"}, val, "Should return inserted value")

	// Test insert duplicate value for same key
	err = tree.Insert(ctx, storage, "key1", "value2")
	require.NoError(t, err, "Insert duplicate value should not error")

	// Verify both values exist
	val, found, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Search should not error")
	require.True(t, found, "Should find key with multiple values")
	require.Equal(t, []string{"value1", "value2"}, val, "Should return all values for key")

	// Test insert same key-value pair again (should not duplicate)
	err = tree.Insert(ctx, storage, "key1", "value1")
	require.NoError(t, err, "Insert existing key-value should not error")

	// Verify no duplicate values
	val, found, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Search should not error")
	require.True(t, found, "Should still find key after inserting duplicate value")
	require.Len(t, val, 2, "Should not create duplicate values")

	// Test insert multiple different keys
	err = tree.Insert(ctx, storage, "key2", "value3")
	require.NoError(t, err, "Insert second key should not error")
	err = tree.Insert(ctx, storage, "key3", "value4")
	require.NoError(t, err, "Insert third key should not error")

	// Verify all keys can be found
	for _, key := range []string{"key1", "key2", "key3"} {
		_, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Search should not error for key %s", key)
		require.True(t, found, "Should find key %s", key)
	}
}

func TestBPlusTreeInsertionWithSplitting(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	// Insert keys that will cause leaf splitting
	err := tree.Insert(ctx, storage, "10", "value10")
	require.NoError(t, err, "Failed to insert key 10")

	err = tree.Insert(ctx, storage, "20", "value20")
	require.NoError(t, err, "Failed to insert key 20")

	// This should cause a leaf split
	err = tree.Insert(ctx, storage, "30", "value30")
	require.NoError(t, err, "Failed to insert key 30")

	// Verify all values are accessible
	testCases := []struct {
		key   string
		value []string
	}{
		{"10", []string{"value10"}},
		{"20", []string{"value20"}},
		{"30", []string{"value30"}},
	}

	for _, tc := range testCases {
		val, found, err := tree.Search(ctx, storage, tc.key)
		require.NoError(t, err, fmt.Sprintf("Error when getting key %v", tc.key))
		require.True(t, found, fmt.Sprintf("Should find inserted key %v", tc.key))
		require.Equal(t, tc.value, val, fmt.Sprintf("Retrieved value should match inserted value for key %v", tc.key))
	}

	// Continue inserting to create internal node splits
	err = tree.Insert(ctx, storage, "40", "value40")
	require.NoError(t, err, "Failed to insert key 40")

	err = tree.Insert(ctx, storage, "50", "value50")
	require.NoError(t, err, "Failed to insert key 50")

	err = tree.Insert(ctx, storage, "60", "value60")
	require.NoError(t, err, "Failed to insert key 60")

	err = tree.Insert(ctx, storage, "70", "value70")
	require.NoError(t, err, "Failed to insert key 70")

	err = tree.Insert(ctx, storage, "80", "value80")
	require.NoError(t, err, "Failed to insert key 80")

	// err = tree.Insert(ctx, storage, "90", "value90")
	// require.NoError(t, err, "Failed to insert key 90")

	// Verify all values after more complex splitting
	for _, tc := range []struct {
		key   string
		value []string
	}{
		{"10", []string{"value10"}},
		{"20", []string{"value20"}},
		{"30", []string{"value30"}},
		{"40", []string{"value40"}},
		{"50", []string{"value50"}},
		{"60", []string{"value60"}},
		{"70", []string{"value70"}},
		{"80", []string{"value80"}},
	} {
		val, found, err := tree.Search(ctx, storage, tc.key)
		require.NoError(t, err, fmt.Sprintf("Error when getting key %v", tc.key))
		require.True(t, found, fmt.Sprintf("Should find inserted key %v", tc.key))
		require.Equal(t, tc.value, val, fmt.Sprintf("Retrieved value should match inserted value for key %v", tc.key))
	}
}

func TestBPlusTreeDelete(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

	// Insert keys
	keys := []string{"a", "b", "c", "d", "e"}
	for i, key := range keys {
		err := tree.Insert(ctx, storage, key, strconv.Itoa(i+1))
		require.NoError(t, err, "Failed to insert key")
	}

	// Test deleting from the middle
	deleted, err := tree.Delete(ctx, storage, "c")
	require.NoError(t, err, "Failed to delete key")
	require.True(t, deleted, "Should successfully delete key 'c'")

	// Verify deletion
	_, found, err := tree.Search(ctx, storage, "c")
	require.NoError(t, err, "Error when getting deleted key")
	require.False(t, found, "Should not find deleted key")

	// Verify remaining keys
	for _, key := range []string{"a", "b", "d", "e"} {
		val, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Error when getting key")
		require.True(t, found, "Should find remaining key")

		// Original index in the keys slice
		expectedVal := []string{}
		if key == "a" {
			expectedVal = []string{"1"}
		} else if key == "b" {
			expectedVal = []string{"2"}
		} else if key == "d" {
			expectedVal = []string{"4"}
		} else if key == "e" {
			expectedVal = []string{"5"}
		}

		require.Equal(t, expectedVal, val, "Retrieved value should match expected")
	}

	// Delete first key
	deleted, err = tree.Delete(ctx, storage, "a")
	require.NoError(t, err, "Failed to delete first key")
	require.True(t, deleted, "Should successfully delete first key")

	// Delete last key
	deleted, err = tree.Delete(ctx, storage, "e")
	require.NoError(t, err, "Failed to delete last key")
	require.True(t, deleted, "Should successfully delete last key")

	// Verify only "b" and "d" remain
	for _, key := range []string{"b", "d"} {
		_, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Error when getting key")
		require.True(t, found, "Should find remaining key")
	}

	// Verify "a" and "e" are gone
	for _, key := range []string{"a", "e"} {
		_, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Error when getting deleted key")
		require.False(t, found, "Should not find deleted key")
	}
}

func TestBPlusTreeDeleteValue(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

	// Insert a key with multiple values
	err := tree.Insert(ctx, storage, "key1", "value1")
	require.NoError(t, err, "Failed to insert first value")
	err = tree.Insert(ctx, storage, "key1", "value2")
	require.NoError(t, err, "Failed to insert second value")
	err = tree.Insert(ctx, storage, "key1", "value3")
	require.NoError(t, err, "Failed to insert third value")

	// Verify all values are accessible
	values, found, err := tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Error when getting key")
	require.True(t, found, "Should find inserted key")
	require.Equal(t, []string{"value1", "value2", "value3"}, values, "Retrieved values should match inserted values")

	// Delete a specific value
	deleted, err := tree.DeleteValue(ctx, storage, "key1", "value2")
	require.NoError(t, err, "Failed to delete value")
	require.True(t, deleted, "Should successfully delete value")

	// Verify the value was deleted
	values, found, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Error when getting key after deletion")
	require.True(t, found, "Should still find key after value deletion")
	require.Equal(t, []string{"value1", "value3"}, values, "Retrieved values should not include deleted value")

	// Delete another value
	deleted, err = tree.DeleteValue(ctx, storage, "key1", "value1")
	require.NoError(t, err, "Failed to delete second value")
	require.True(t, deleted, "Should successfully delete second value")

	// Verify the value was deleted
	values, found, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Error when getting key after second deletion")
	require.True(t, found, "Should still find key after second value deletion")
	require.Equal(t, []string{"value3"}, values, "Retrieved values should only include remaining value")

	// Delete the last value
	deleted, err = tree.DeleteValue(ctx, storage, "key1", "value3")
	require.NoError(t, err, "Failed to delete last value")
	require.True(t, deleted, "Should successfully delete last value")

	// Verify the key is no longer accessible
	_, found, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err, "Error when getting key after all values deleted")
	require.False(t, found, "Should not find key after all values deleted")

	// Try to delete a non-existent value
	deleted, err = tree.DeleteValue(ctx, storage, "key1", "nonexistent")
	require.Nil(t, err, "Should not error when deleting non-existent value")
	require.False(t, deleted, "DeleteValue should return false for non-existent value")

	// Try to delete a value from a non-existent key
	deleted, err = tree.DeleteValue(ctx, storage, "nonexistent", "value1")
	require.Nil(t, err, "Should not error when deleting from non-existent key")
	require.False(t, deleted, "DeleteValue should return false for non-existent key")
}

func TestBPlusTreeLargeDataSet(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 32})

	const numKeys = 10_000

	// Generate a pseudo-random but deterministic sequence of keys using a simple hash
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		// Use a simple permutation: (i*7919 + 104729) % 1000003
		k := (i*7919 + 104729) % 1000003
		keys[i] = strconv.Itoa(k)
	}

	// Insert all keys
	for _, key := range keys {
		err := tree.Insert(ctx, storage, key, keyValue(key))
		require.NoError(t, err, "Failed to insert key %s", key)
	}

	// Verify all keys exist
	for _, key := range keys {
		val, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Error when getting key %s", key)
		require.True(t, found, "Should find key %s", key)
		require.Equal(t, []string{keyValue(key)}, val, "Retrieved value should match for key %s", key)
	}

	// Delete every other key (even indices)
	for i := 0; i < numKeys; i += 2 {
		deleted, err := tree.Delete(ctx, storage, keys[i])
		require.NoError(t, err, "Failed to delete key %s", keys[i])
		require.True(t, deleted, "Should successfully delete key %s", keys[i])
	}

	// Verify odd-indexed keys exist and even-indexed keys don't
	for i, key := range keys {
		val, found, err := tree.Search(ctx, storage, key)
		require.NoError(t, err, "Error when getting key %s", key)

		if i%2 == 1 {
			// Odd-indexed keys should exist
			require.True(t, found, "Should find odd-indexed key %s", key)
			require.Equal(t, []string{keyValue(key)}, val, "Retrieved value should match for key %s", key)
		} else {
			// Even-indexed keys should be deleted
			require.False(t, found, "Should not find even-indexed key %s", key)
			require.Empty(t, val, "Value should be empty for deleted key %s", key)
		}
	}
}

func TestBPlusTreeConcurrency(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

	// Test concurrent reads
	t.Run("ConcurrentReads", func(t *testing.T) {
		// Insert some test data
		err := tree.Insert(ctx, storage, "1", "value1")
		require.NoError(t, err)

		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		// Launch multiple goroutines to read concurrently
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				val, found, err := tree.Search(ctx, storage, "1")
				if err != nil {
					errChan <- fmt.Errorf("error getting value: %w", err)
					return
				}
				if !found {
					errChan <- fmt.Errorf("value not found")
					return
				}
				if !reflect.DeepEqual(val, []string{"value1"}) {
					errChan <- fmt.Errorf("expected value (%v), got (%v)", []string{"value1"}, val)
					return
				}
			}()
		}

		// Wait for all goroutines to complete with a timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines completed
		case <-time.After(5 * time.Second):
			t.Fatal("test timed out waiting for goroutines to complete")
		}

		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Error(err)
		}
	})

	// Test concurrent writes
	t.Run("ConcurrentWrites", func(t *testing.T) {
		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		// Launch multiple goroutines to write concurrently
		for i := range 10 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				err := tree.Insert(ctx, storage, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
				if err != nil {
					errChan <- fmt.Errorf("error inserting key (%d): %w", i, err)
					return
				}
			}(i)
		}

		// Wait for all goroutines to complete with a timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines completed
		case <-time.After(5 * time.Second):
			t.Fatal("test timed out waiting for goroutines to complete")
		}

		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Error(err)
		}

		// Verify all values were inserted
		for i := range 10 {
			val, found, err := tree.Search(ctx, storage, fmt.Sprintf("key%d", i))
			require.NoError(t, err, "Error when getting key %d", i)
			require.True(t, found, "Should find key %d", i)
			require.Equal(t, []string{fmt.Sprintf("value%d", i)}, val, "Retrieved value should match for key %d", i)
		}
	})

	// Test concurrent DeleteValue operations
	t.Run("ConcurrentDeleteValue", func(t *testing.T) {
		// Insert a key with multiple values
		for i := range 5 {
			err := tree.Insert(ctx, storage, "100", fmt.Sprintf("value%d", i))
			require.NoError(t, err, "Failed to insert value %d", i)
		}

		// Verify all values are accessible
		values, found, err := tree.Search(ctx, storage, "100")
		require.NoError(t, err, "Error when getting key")
		require.True(t, found, "Should find inserted key")
		require.Len(t, values, 5, "Should have 5 values")

		var wg sync.WaitGroup
		errChan := make(chan error, 5)

		// Launch multiple goroutines to delete values concurrently
		for i := range 5 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				_, err := tree.DeleteValue(ctx, storage, "100", fmt.Sprintf("value%d", i))
				if err != nil {
					errChan <- fmt.Errorf("error deleting value %d: %w", i, err)
					return
				}
			}(i)
		}

		// Wait for all goroutines to complete with a timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines completed
		case <-time.After(5 * time.Second):
			t.Fatal("test timed out waiting for goroutines to complete")
		}

		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Error(err)
		}

		// Verify the key is no longer accessible
		_, found, err = tree.Search(ctx, storage, "100")
		require.NoError(t, err, "Error when getting key after all values deleted")
		require.False(t, found, "Should not find key after all values deleted")
	})
}

func TestBPlusTreeEdgeCases(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	t.Run("SplitAtRoot", func(t *testing.T) {
		// Insert keys that will cause root split
		err := tree.Insert(ctx, storage, "1", "value1")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "2", "value2")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "3", "value3") // This should cause a split
		require.NoError(t, err)

		// Verify all values are accessible
		for i := 1; i <= 3; i++ {
			val, found, err := tree.Search(ctx, storage, strconv.Itoa(i))
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, []string{fmt.Sprintf("value%d", i)}, val)
		}
	})

	t.Run("SplitAtLeaf", func(t *testing.T) {
		// Insert more keys to cause leaf splits
		err := tree.Insert(ctx, storage, "4", "value4")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "5", "value5")
		require.NoError(t, err)
		err = tree.Insert(ctx, storage, "6", "value6") // This should cause a leaf split
		require.NoError(t, err)

		// Verify all values are accessible
		for i := 1; i <= 6; i++ {
			val, found, err := tree.Search(ctx, storage, strconv.Itoa(i))
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, []string{fmt.Sprintf("value%d", i)}, val)
		}
	})
}

// MockStoragestorage simulates storage errors
type MockStoragestorage struct {
	*NodeStorage
	shouldFail bool
}

func (m *MockStoragestorage) PutNode(ctx context.Context, node *Node) error {
	if m.shouldFail {
		return fmt.Errorf("simulated storage error")
	}
	return m.NodeStorage.PutNode(ctx, node)
}

func (m *MockStoragestorage) GetNode(ctx context.Context, id string) (*Node, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("simulated storage error")
	}
	return m.NodeStorage.GetNode(ctx, id)
}

func TestBPlusTreeStorageErrors(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}
	basestorage, err := NewNodeStorage(s)
	require.NoError(t, err, "Failed to create storage storage")
	mockstorage := &MockStoragestorage{
		NodeStorage: basestorage,
		shouldFail:  false,
	}

	tree, err := InitializeBPlusTree(ctx, mockstorage, &BPlusTreeConfig{TreeID: "storage_errors_test", Order: 4})
	require.NoError(t, err, "Failed to create B+ tree")

	// Insert some test data
	err = tree.Insert(ctx, mockstorage, "key1", "value1")
	require.NoError(t, err)

	t.Run("StorageFailureDuringGet", func(t *testing.T) {
		mockstorage.shouldFail = true
		_, _, err := tree.Search(ctx, mockstorage, "key1")
		require.Error(t, err, "Should error when storage fails")
		require.Contains(t, err.Error(), "simulated storage error")
		mockstorage.shouldFail = false
	})

	t.Run("StorageFailureDuringInsert", func(t *testing.T) {
		mockstorage.shouldFail = true
		err := tree.Insert(ctx, mockstorage, "key2", "value2")
		require.Error(t, err, "Should error when storage fails")
		require.Contains(t, err.Error(), "simulated storage error")
		mockstorage.shouldFail = false
	})

	t.Run("StorageFailureDuringDelete", func(t *testing.T) {
		mockstorage.shouldFail = true
		deleted, err := tree.Delete(ctx, mockstorage, "key1")
		require.Error(t, err, "Should error when storage fails")
		require.False(t, deleted, "Delete should not succeed when storage fails")
		require.Contains(t, err.Error(), "simulated storage error")
		mockstorage.shouldFail = false
	})

	t.Run("StorageFailureDuringDeleteValue", func(t *testing.T) {
		// Insert a key with multiple values
		err = tree.Insert(ctx, mockstorage, "key3", "value1")
		require.NoError(t, err)
		err = tree.Insert(ctx, mockstorage, "key3", "value2")
		require.NoError(t, err)

		mockstorage.shouldFail = true
		deleted, err := tree.DeleteValue(ctx, mockstorage, "key3", "value1")
		require.Error(t, err, "Should error when storage fails")
		require.False(t, deleted, "DeleteValue should not succeed when storage fails")
		require.Contains(t, err.Error(), "simulated storage error")
		mockstorage.shouldFail = false
	})

	t.Run("RecoveryAfterStorageFailure", func(t *testing.T) {
		// Verify tree is still usable after storage errors
		val, found, err := tree.Search(ctx, mockstorage, "key1")
		require.NoError(t, err, "Should work after storage recovers")
		require.True(t, found, "Should find key after storage recovers")
		require.Equal(t, []string{"value1"}, val, "Value should be correct after storage recovers")
	})
}

// TODO: This isn't complete enough...
func TestBPlusTreeDuplicateValues(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 4})

	// Insert initial values
	err := tree.Insert(ctx, storage, "key1", "value1")
	require.NoError(t, err)
	err = tree.Insert(ctx, storage, "key1", "value2")
	require.NoError(t, err)

	// Try to insert duplicate values
	err = tree.Insert(ctx, storage, "key1", "value1")
	require.NoError(t, err) // Should not error, but should not add duplicate
	err = tree.Insert(ctx, storage, "key1", "value2")
	require.NoError(t, err) // Should not error, but should not add duplicate

	// Verify values
	values, exists, err := tree.Search(ctx, storage, "key1")
	require.NoError(t, err)
	require.True(t, exists)
	require.Len(t, values, 2)
	require.Contains(t, values, "value1")
	require.Contains(t, values, "value2")

	// Insert a new value
	err = tree.Insert(ctx, storage, "key1", "value3")
	require.NoError(t, err)

	// Verify values again
	values, exists, err = tree.Search(ctx, storage, "key1")
	require.NoError(t, err)
	require.True(t, exists)
	require.Len(t, values, 3)
	require.Contains(t, values, "value1")
	require.Contains(t, values, "value2")
	require.Contains(t, values, "value3")
}

// TestLeafNodeLinking tests that the NextID and PreviousID fields are properly set during leaf operations
func TestLeafNodeLinking(t *testing.T) {
	ctx, storage, tree := initTest(t, &BPlusTreeConfig{Order: 3})

	t.Run("SingleLeafNode", func(t *testing.T) {
		// Insert into root leaf - should have empty NextID initially
		err := tree.Insert(ctx, storage, "0", "value0")
		require.NoError(t, err, "Failed to insert key0")

		root, err := tree.getRoot(ctx, storage)
		require.NoError(t, err, "Failed to get root")
		require.True(t, root.IsLeaf, "Root should be a leaf")
		require.Empty(t, root.NextID, "Single leaf should have empty NextID")
		require.Empty(t, root.PreviousID, "Single leaf should have empty PreviousID")
	})

	t.Run("LeafSplitCreatesTwoLinkedLeaves", func(t *testing.T) {
		// Insert more keys to force a leaf split
		err := tree.Insert(ctx, storage, "1", "value1")
		require.NoError(t, err, "Failed to insert key1")

		// This should cause a leaf split (order=3, so max 2 keys per leaf)
		err = tree.Insert(ctx, storage, "2", "value2")
		require.NoError(t, err, "Failed to insert key2")

		// Find the leftmost leaf
		leftmost, err := tree.findLeftmostLeaf(ctx, storage)
		require.NoError(t, err, "Failed to find leftmost leaf")

		// Verify the leaf has a NextID
		require.NotEmpty(t, leftmost.NextID, "Leftmost leaf should have NextID after split")

		// Verify the leaf has a PreviousID
		require.Empty(t, leftmost.PreviousID, "Leftmost leaf should have empty PreviousID")

		// Load the next leaf
		rightLeaf, err := storage.GetNode(ctx, leftmost.NextID)
		require.NoError(t, err, "Failed to load right leaf")
		require.True(t, rightLeaf.IsLeaf, "Next node should be a leaf")

		// The rightmost leaf should have empty NextID
		require.Empty(t, rightLeaf.NextID, "Rightmost leaf should have empty NextID")

		// Verify the leaf has a PreviousID
		require.NotEmpty(t, rightLeaf.PreviousID, "Rightmost leaf should have PreviousID")

		// Verify keys are properly distributed
		allKeys := append(leftmost.Keys, rightLeaf.Keys...)
		require.ElementsMatch(t, []string{"0", "1", "2"}, allKeys, "All keys should be present across leaves")
	})

	t.Run("NextIDSequentialTraversal", func(t *testing.T) {
		// Insert more keys to create multiple leaf splits
		for i := 3; i <= 9; i++ {
			key := strconv.Itoa(i)
			err := tree.Insert(ctx, storage, key, keyValue(key))
			require.NoError(t, err, "Failed to insert key%d", i)
		}

		var allKeys []string
		// Traverse through all leaves using NextID
		current, err := tree.findLeftmostLeaf(ctx, storage)
		require.NoError(t, err, "Failed to find leftmost leaf")

		for current != nil {
			allKeys = append(allKeys, current.Keys...)
			if current.NextID == "" {
				break
			}
			current, err = storage.GetNode(ctx, current.NextID)
			require.NoError(t, err, "Failed to load next leaf")
		}

		// Verify all keys are present and in order
		expectedKeys := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
		require.Equal(t, expectedKeys, allKeys, "Keys should be in sorted order through leaf traversal")
	})

	t.Run("PreviousIDSequentialTraversal", func(t *testing.T) {
		var allKeys []string
		// Traverse through all leaves using PreviousID
		current, err := tree.findRightmostLeaf(ctx, storage)
		require.NoError(t, err, "Failed to find leftmost leaf")

		for current != nil {
			slices.Reverse(current.Keys) // Revert the slice for the order to be correct...
			allKeys = append(allKeys, current.Keys...)
			if current.PreviousID == "" {
				break
			}

			current, err = storage.GetNode(ctx, current.PreviousID)
			require.NoError(t, err, "Failed to load previous leaf")
		}

		// Verify all keys are present and in order
		expectedKeys := []string{"9", "8", "7", "6", "5", "4", "3", "2", "1", "0"}
		require.Equal(t, expectedKeys, allKeys, "Keys should be in sorted order through leaf traversal")
	})
}

// TestMultiTreeOperations tests that multiple trees can operate independently
func TestMultiTreeOperations(t *testing.T) {
	ctx, storage, _ := initTest(t, &BPlusTreeConfig{Order: 4})

	// Create two trees with different names
	config1, err := NewBPlusTreeConfig("tree1", 4)
	require.NoError(t, err)
	tree1, err := InitializeBPlusTree(ctx, storage, config1)
	require.NoError(t, err, "Failed to create tree1")

	config2, err := NewBPlusTreeConfig("tree2", 4)
	require.NoError(t, err)
	tree2, err := InitializeBPlusTree(ctx, storage, config2)
	require.NoError(t, err, "Failed to create tree2")

	// Insert data into tree1
	err = tree1.Insert(ctx, storage, "key1", "tree1_value1")
	require.NoError(t, err, "Failed to insert into tree1")
	err = tree1.Insert(ctx, storage, "key2", "tree1_value2")
	require.NoError(t, err, "Failed to insert into tree1")

	// Insert data into tree2
	err = tree2.Insert(ctx, storage, "key1", "tree2_value1")
	require.NoError(t, err, "Failed to insert into tree2")
	err = tree2.Insert(ctx, storage, "key3", "tree2_value3")
	require.NoError(t, err, "Failed to insert into tree2")

	// Verify tree1 data
	val, found, err := tree1.Search(ctx, storage, "key1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"tree1_value1"}, val)

	val, found, err = tree1.Search(ctx, storage, "key2")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"tree1_value2"}, val)

	// key3 should not exist in tree1
	_, found, err = tree1.Search(ctx, storage, "key3")
	require.NoError(t, err)
	require.False(t, found)

	// Verify tree2 data
	val, found, err = tree2.Search(ctx, storage, "key1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"tree2_value1"}, val)

	val, found, err = tree2.Search(ctx, storage, "key3")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"tree2_value3"}, val)

	// key2 should not exist in tree2
	_, found, err = tree2.Search(ctx, storage, "key2")
	require.NoError(t, err)
	require.False(t, found)
}
