// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
)

// ErrReadOnly is returned when a backend does not support
// writing. This can be caused by a read-only replica or secondary
// cluster operation.
var ErrReadOnly = errors.New("cannot write to readonly storage")

// ErrSetupReadOnly is returned when a write operation is attempted on a
// storage while the backend is still being setup.
var ErrSetupReadOnly = errors.New("cannot write to storage during setup")

// Plugins using Paths.WriteForwardedStorage will need to use this sentinel
// in their path to write cross-cluster. See the description of that parameter
// for more information.
const PBPWFClusterSentinel = "{{clusterId}}"

// Default number of elements returned from a single call to ListPage. This
// should roughly fit in 2MB of memory assuming an excessively long path
// length (400 characters).
const DefaultScanViewPageLimit = 2500

// Storage is the way that logical backends are able read/write data.
type Storage interface {
	List(context.Context, string) ([]string, error)
	ListPage(context.Context, string, string, int) ([]string, error)
	Get(context.Context, string) (*StorageEntry, error)
	Put(context.Context, *StorageEntry) error
	Delete(context.Context, string) error
}

// StorageEntry is the entry for an item in a Storage implementation.
type StorageEntry struct {
	Key      string
	Value    []byte
	SealWrap bool
}

// DecodeJSON decodes the 'Value' present in StorageEntry.
func (e *StorageEntry) DecodeJSON(out interface{}) error {
	return jsonutil.DecodeJSON(e.Value, out)
}

// StorageEntryJSON creates a StorageEntry with a JSON-encoded value.
func StorageEntryJSON(k string, v interface{}) (*StorageEntry, error) {
	encodedBytes, err := jsonutil.EncodeJSON(v)
	if err != nil {
		return nil, fmt.Errorf("failed to encode storage entry: %w", err)
	}

	return &StorageEntry{
		Key:   k,
		Value: encodedBytes,
	}, nil
}

type ClearableView interface {
	List(context.Context, string) ([]string, error)
	ListPage(context.Context, string, string, int) ([]string, error)
	Delete(context.Context, string) error
}

var _ ClearableView = Storage(nil)

// ScanView is used to scan all the keys in a view iteratively
func ScanView(ctx context.Context, view ClearableView, cb func(path string)) error {
	return ScanViewWithLogger(ctx, view, nil, cb)
}

func ScanViewWithLogger(ctx context.Context, view ClearableView, logger hclog.Logger, cb func(path string)) error {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	// Pagination exposes more granular callback information.
	return ScanViewPaginated(ctx, view, logger, DefaultScanViewPageLimit, func(page int, index int, path string) (cont bool, err error) {
		cb(path)
		return true, nil
	})
}

func ScanViewPaginated(ctx context.Context, view ClearableView, logger hclog.Logger, pageSize int, cb func(page int, index int, path string) (cont bool, err error)) error {
	if txView, ok := view.(Transactional); ok {
		txn, err := txView.BeginReadOnlyTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		// This transaction is not used for any operations within the scan.
		defer txn.Rollback(ctx)
		view = txn.(ClearableView)
	}

	return scanViewPaginated(ctx, view, logger, pageSize, cb)
}

func scanViewPaginated(ctx context.Context, view ClearableView, logger hclog.Logger, pageSize int, cb func(page int, index int, path string) (cont bool, err error)) error {
	frontier := []string{""}
	for len(frontier) > 0 {
		n := len(frontier)
		current := frontier[n-1]
		frontier = frontier[:n-1]
		logger.Trace("iterating frontier", "n", n, "current", current, "remaining", len(frontier))

		// List the contents using pagination.
		var after string
		var page int
		for {
			contents, err := view.ListPage(ctx, current, after, pageSize)
			if err != nil {
				return fmt.Errorf("list page %v failed at path %q: %w - %v / %v / %v", page, current, err, frontier, contents, after)
			}

			logger.Trace("listing page", "current", current, "after", after, "pageSize", pageSize, "contents", len(contents))

			if len(contents) == 0 {
				break
			}

			after = contents[len(contents)-1]
			page += 1

			// Handle the contents in the directory
			for index, c := range contents {
				// Exit if the context has been canceled
				if ctx.Err() != nil {
					return ctx.Err()
				}
				fullPath := current + c
				if strings.HasSuffix(c, "/") {
					frontier = append(frontier, fullPath)
				} else {
					cont, err := cb(page, index, fullPath)
					if err != nil || !cont {
						return err
					}
				}
			}

			if after == "" && len(contents) == 1 && pageSize > 1 {
				// In this case, contents[0] == after == "". We hit this when
				// a key is written to storage with a trailing slash (baz/);
				// this is still a valid entry, so by semantics of list,
				// list(baz/) = "", if nothing else resides under baz/. This
				// is hit in some incorrect path joining operations and so
				// must still be able to function correctly. Setting after=""
				// is the default value and must include "" in the listing, so
				// if we have an adequately large page size and the empty
				// string is what we got, we know there's nothing else there
				// and thus we can break.
				break
			}
		}
	}
	return nil
}

// CollectKeys is used to collect all the keys in a view
func CollectKeys(ctx context.Context, view ClearableView) ([]string, error) {
	return CollectKeysWithPrefix(ctx, view, "")
}

// CollectKeysWithPrefix is used to collect all the keys in a view with a given prefix string
func CollectKeysWithPrefix(ctx context.Context, view ClearableView, prefix string) ([]string, error) {
	return CollectKeysWithPrefixWithLogger(ctx, view, nil, prefix)
}

func CollectKeysWithPrefixWithLogger(ctx context.Context, view ClearableView, logger hclog.Logger, prefix string) ([]string, error) {
	var keys []string

	cb := func(path string) {
		if strings.HasPrefix(path, prefix) {
			keys = append(keys, path)
		}
	}

	// Scan for all the keys
	if err := ScanViewWithLogger(ctx, view, logger, cb); err != nil {
		return nil, err
	}
	return keys, nil
}

// CountKeys is used to identify how many keys exist in a view.
func CountKeys(ctx context.Context, view ClearableView) (int, error) {
	var count int

	if err := ScanView(ctx, view, func(path string) {
		count += 1
	}); err != nil {
		return -1, err
	}

	return count, nil
}

// ClearView is used to delete all the keys in a view
func ClearView(ctx context.Context, view ClearableView) error {
	return ClearViewWithLogging(ctx, view, nil)
}

func ClearViewWithLogging(ctx context.Context, view ClearableView, logger hclog.Logger) error {
	if view == nil {
		return nil
	}

	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	return ClearViewWithPagination(ctx, view, logger)
}

func ClearViewWithPagination(ctx context.Context, view ClearableView, logger hclog.Logger) error {
	countKeys, err := CountKeys(ctx, view)
	if err != nil {
		return fmt.Errorf("failed to count keys: %w", err)
	}

	logger.Debug("clearing paginated view", "total_keys", countKeys)

	var pctDone int
	var removedKeys int
	if err := ScanViewPaginated(ctx, view, logger, DefaultScanViewPageLimit, func(page int, index int, path string) (bool, error) {
		// Rather than keep trying to do stuff with a canceled context, bail;
		// storage will fail anyways
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		if err := view.Delete(ctx, path); err != nil {
			return false, err
		}

		removedKeys += 1

		newPctDone := removedKeys * 100.0 / countKeys
		if int(newPctDone) > pctDone {
			pctDone = int(newPctDone)
			logger.Trace("view deletion progress", "percent", pctDone, "keys_deleted", removedKeys)
		}

		return true, nil
	}); err != nil {
		return err
	}

	logger.Debug("paginated view cleared")

	return nil
}

func ClearViewWithoutPagination(ctx context.Context, view ClearableView, logger hclog.Logger) error {
	// Collect all the keys
	keys, err := CollectKeys(ctx, view)
	if err != nil {
		return err
	}

	logger.Debug("clearing view", "total_keys", len(keys))

	// Delete all the keys
	var pctDone int
	for idx, key := range keys {
		// Rather than keep trying to do stuff with a canceled context, bail;
		// storage will fail anyways
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := view.Delete(ctx, key); err != nil {
			return err
		}

		newPctDone := idx * 100.0 / len(keys)
		if int(newPctDone) > pctDone {
			pctDone = int(newPctDone)
			logger.Trace("view deletion progress", "percent", pctDone, "keys_deleted", idx)
		}
	}

	logger.Debug("view cleared")

	return nil
}

// HandleListPage provides a helper for processing paginated storage lists.
// It supports both item-level and batch-level callbacks for flexibility.
//
// itemCallback: Invoked for each individual entry in the paginated list.
//   - Parameters: `page` (page index), `index` (entry index in the page), and `entry` (the storage entry).
//   - Return: A boolean `cont` (whether to continue processing) and an `error` if an issue occurs.
//
// batchCallback: Invoked after processing a full batch of entries in the current page.
//   - Parameters: `page` (page index) and `entries` (all entries in the current batch).
//   - Return: A boolean `cont` (whether to continue processing) and an `error` if an issue occurs.
//
// The callbacks are executed sequentially, with `itemCallback` processing each entry individually,
// followed by `batchCallback` handling the entire batch.
func HandleListPage(
	ctx context.Context,
	storage Storage,
	prefix string,
	limit int,
	itemCallback func(page int, index int, entry string) (cont bool, err error),
	batchCallback func(page int, entries []string) (cont bool, err error),
) error {
	var page int
	var after string
	for {
		// Check for context cancellation. Storage should do this as well.
		if err := ctx.Err(); err != nil {
			return err
		}

		// Fetch the next page. Storage should check for context cancellation.
		entries, err := storage.ListPage(ctx, prefix, after, limit)
		if err != nil {
			return err
		}

		// Exit if no entries are returned
		if len(entries) == 0 {
			break
		}

		// Process each entry in the page
		for index, entry := range entries {
			// Check for context cancellation. Storage should do this as well.
			if err := ctx.Err(); err != nil {
				return err
			}

			if itemCallback != nil {
				cont, err := itemCallback(page, index, entry)
				if err != nil || !cont {
					return err
				}
			}
		}

		// Process the entire batch
		if batchCallback != nil {
			cont, err := batchCallback(page, entries)
			if err != nil || !cont {
				return err
			}
		}

		// Stop since all certs have already been processed
		if limit <= 0 {
			break
		}

		// Stop since this is the last page; prevents 1 unnecessary call to ListPage
		if len(entries) < limit {
			break
		}

		// Update after for the next page
		after = entries[len(entries)-1]
		page++
	}

	return nil
}
