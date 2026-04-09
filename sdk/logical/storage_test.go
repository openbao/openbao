// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var keyList = []string{
	"a",
	"b",
	"d",
	"foo",
	"foo42",
	"foo/a/b/c",
	"c/d/e/f/g",
	"bar/bar/bar",
	"bar/bar/bar/bar",
	"bar/bar/bar/bar/",
}

func TestScanView(t *testing.T) {
	s := prepKeyStorage(t)

	keys := make([]string, 0)
	err := ScanView(t.Context(), s, func(path string) {
		keys = append(keys, path)
	})
	require.NoError(t, err)
	require.Equal(t, keyList, keys)
}

func TestScanView_CancelContext(t *testing.T) {
	s := prepKeyStorage(t)

	ctx, cancelCtx := context.WithCancel(t.Context())
	var i int
	err := ScanView(ctx, s, func(path string) {
		cancelCtx()
		i++
	})

	assert.Error(t, err, "Want context cancel err, got none")
	assert.Equal(t, 1, i, "Want i==1")
}

func TestScanViewPaginated(t *testing.T) {
	s := prepKeyStorage(t)

	keys := make([]string, 0)
	err := ScanViewWithLogger(t.Context(), s, nil, func(path string) {
		keys = append(keys, path)
	})
	require.NoError(t, err)
	require.Equal(t, keyList, keys)

	// Validate that recursing into a folder which only has references to
	// itself and/or files which bear the same name works.
	v := NewStorageView(s, "bar/")
	logger := hclog.NewNullLogger()
	for pageSize := 2; pageSize < 10; pageSize++ {
		keys = make([]string, 0)
		err = ScanViewPaginated(t.Context(), v, logger, pageSize, func(_ int, _ int, path string) (bool, error) {
			keys = append(keys, path)
			return true, nil
		})
		require.NoError(t, err)

		trimmedExpected := make([]string, 0)
		for _, path := range keyList[len(keyList)-3:] {
			trimmedExpected = append(trimmedExpected, path[len("bar/"):])
		}
		require.Equal(t, trimmedExpected, keys, "page size: %v", pageSize)
	}
}

func TestCollectKeys(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, keyList, keys)
}

func TestCollectKeysPrefix(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeysWithPrefix(t.Context(), s, "foo")
	require.NoError(t, err)

	exp := []string{
		"foo",
		"foo42",
		"foo/a/b/c",
	}
	require.Equal(t, exp, keys)
}

func TestClearView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearView(t.Context(), s)
	require.NoError(t, err)

	keys, err = CollectKeys(t.Context(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestClearPaginatedView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearViewWithPagination(t.Context(), s, hclog.NewNullLogger())
	require.NoError(t, err)

	keys, err = CollectKeys(t.Context(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestClearUnpaginatedView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearViewWithoutPagination(t.Context(), s, hclog.NewNullLogger())
	require.NoError(t, err)

	keys, err = CollectKeys(t.Context(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestHandleListPageTermination(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := s.List(t.Context(), "")
	require.NoError(t, err)

	var seenKeys []string
	var batchCount int
	err = HandleListPage(t.Context(), s, "", 2, func(page int, index int, entry string) (bool, error) {
		seenKeys = append(seenKeys, entry)
		return true, nil
	}, func(page int, entries []string) (bool, error) {
		batchCount += 1
		return true, nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, seenKeys, keys)
	require.Equal(t, batchCount, len(keys)/2)

	var immediateCancel bool
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err = HandleListPage(ctx, s, "", 2, func(page int, index int, entry string) (bool, error) {
		immediateCancel = false
		time.Sleep(1 * time.Second)
		return true, nil
	}, func(page int, entries []string) (bool, error) {
		immediateCancel = false
		time.Sleep(1 * time.Second)
		return true, nil
	})

	require.Error(t, err)
	require.False(t, immediateCancel)
	require.Contains(t, err.Error(), "context")
}

func prepKeyStorage(t *testing.T) Storage {
	t.Helper()
	s := &InmemStorage{}

	for _, key := range keyList {
		err := s.Put(t.Context(), &StorageEntry{
			Key:      key,
			Value:    nil,
			SealWrap: false,
		})
		require.NoError(t, err)
	}

	return s
}
