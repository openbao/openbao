package physical

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
)

// Lister allows an ordered, seeking backend to implement ListPage in a
// uniform manner without handling the specifics of paginated list
// themselves.
type Lister struct {
	// Prefix is as given to physical.Backend.ListPage(...).
	Prefix string

	// After is as given to physical.Backend.ListPage(...).
	After string

	// Limit is as given to physical.Backend.ListPage(...).
	Limit int

	// Start is a function which begins iteration, setting the initial value
	// returned by Key(...).
	Start func() error

	// Next is a function which continues iteration, updating the next value
	// returned by Key(...).
	Next func() error

	// Key returns the key at the current iteration position.
	Key func() (string, bool, error)

	// Deleted returns whether the given fully resolved path has been deleted.
	//
	// This is used with reconciling read-write transactions: those which
	// maintain written/updated state in memory but use a consistent read-only
	// snapshot as the backing layer. In this case, the above Start(...),
	// Next(...), and Key(...) functions return the state as of the read-only
	// storage view and Lister.ListPage(...) will resolve the discrepancies.
	Deleted func(path string) bool

	// Inserted returns an iterator over all insertions in the given
	// transaction. See note about Delete(...) above.
	Inserted func() iter.Seq[string]
}

// SeekPrefix returns the joined prefix of the first element, assuming a strict
// greater-than seek logic. Lister handles both greater-than and
// greater-than-equal seek logic.
func (l *Lister) SeekPrefix() (string, []byte) {
	slash := "/"

	// This is a quirk of how listing works not exercised by our test suite:
	// if you list a specific entry under certain backends, you'd end up with
	// a single result, the entry itself. This is because no subsequent keys
	// were checked by virtue of there being an actual slash and after was
	// empty. As a side effect, ClearView(...) on such a path would actually
	// function and would remove the path. This seems reasonable enough to
	// keep the behavior of, even though the list operation (which enabled
	// this) probably shouldn't have.
	if l.Prefix == "" || l.After == "" || l.Prefix[len(l.Prefix)-1] == '/' || l.After[0] == '/' {
		slash = ""
	}

	result := l.Prefix + slash + l.After
	return result, []byte(result)
}

func (l *Lister) validate() error {
	if l.Start == nil || l.Next == nil || l.Key == nil {
		return errors.New("missing implementation helpers")
	}

	if (l.Deleted != nil) != (l.Inserted != nil) {
		return errors.New("missing reconciling implementation helpers")
	}

	if l.Limit < 0 {
		// Ensure uniformity of limits.
		l.Limit = 0
	}

	return nil
}

func (l *Lister) while(ctx context.Context, listerErr *error, key *string, start *bool, keys []string) bool {
	if ctx.Err() != nil {
		// Context cancelled.
		*listerErr = ctx.Err()
		return false
	}

	if l.Limit > 0 && len(keys) >= l.Limit {
		// Enough keys, can return early.
		return false
	}

	// Progress through the loop.
	increment := l.Next
	if !*start {
		increment = l.Start
		*start = true
	}

	if err := increment(); err != nil {
		*listerErr = err
		return false
	}

	var ok bool
	*key, ok, *listerErr = l.Key()
	if *listerErr != nil {
		return false
	}

	// Otherwise, validate we haven't gone too far.
	return ok && strings.HasPrefix(*key, l.Prefix)
}

// shouldIncludeEntry returns (entryName, isFolder, shouldVisit)
func (l *Lister) shouldIncludeEntry(key string) (string, bool, bool) {
	subKey, ok := strings.CutPrefix(key, l.Prefix)
	if !ok {
		return subKey, false, false
	}

	i := strings.Index(subKey, "/")
	if i == -1 {
		// Not a folder; check if we can skip this entry by suffix.
		if l.After != "" && subKey <= l.After {
			return subKey, false, false
		}

		return subKey, false, true
	}

	// Check if we need to visit the truncated folder path.
	folder := subKey[:i+1]
	if l.After != "" && folder <= l.After {
		return folder, true, false
	}

	return folder, true, true
}

func (l *Lister) inserts() []string {
	var entries []string

	if l.Inserted == nil {
		return entries
	}

	for path := range l.Inserted() {
		entry, _, include := l.shouldIncludeEntry(path)
		if !include {
			continue
		}

		entries = append(entries, entry)
	}

	slices.Sort(entries)
	return slices.Compact(entries)
}

func (l *Lister) ListPage(ctx context.Context) ([]string, []string, error) {
	// List differs from Get in that the latter is a single entry: if an
	// put or delete has occurred in the transaction, it supersedes the
	// value we would've gotten from the underlying data store. Here however,
	// we always want to execute the list and remove entries if there have
	// been writes that affect it.
	//
	// This is complex to do efficiently. We might have deleted an entire
	// subtree that might show up in a list. We could've also added more
	// entries, such that the list is unnecessary.
	//
	// We do this in two steps: perform the underlying list, ignoring results
	// that have been deleted and merging any new writes that occur prior to
	// a given iteration's entry. Finally after the loop, we merge in results
	// that have been added after the last key in the pending list, trimming
	// it down to size.

	if err := l.validate(); err != nil {
		return nil, nil, fmt.Errorf("error validating list parameters: %w", err)
	}

	// We remain two lists of keys: those we expect to be returned to the
	// caller (i.e., the reconciled list), and the list of keys present in
	// storage from our underlying view. This lets callers know what was
	// actually read and use it for conflict detection.
	var keys []string
	var presentKeys []string

	// Because inserts is sorted, we can maintain a single iterator over it.
	inserts := l.inserts()
	offset := 0

	// We track errors and keys explicitly here so that Start(...), Next(...),
	// and Key(...) are allowed to error.
	var listerErr error
	var key string
	var start bool

	// We assume the backend supports seeking around after, however, we'll
	// gracefully handle and skip entries which occur before/at the after
	// point in case this is ambiguous or different. This is only true if
	// prefix is respected though: if we seek before prefix, we'll skip this
	// loop entirely.
	for l.while(ctx, &listerErr, &key, &start, keys) {
		entry, isFolder, shouldVisit := l.shouldIncludeEntry(key)

		// Always track this key as it was present in storage.
		presentKeys = append(presentKeys, key)

		if l.Deleted != nil && l.Deleted(key) {
			// Key was deleted in this transaction so we should skip it.
			continue
		}

		if !shouldVisit {
			// Skip this entry as it doesn't have the correct prefix.
			continue
		}

		// lastKey holds the last key in the keys list for comparison.
		lastKey := ""
		if len(keys) > 0 {
			lastKey = keys[len(keys)-1]
		}

		// Check if we need to add any items inserted in this transaction
		// before we process the item from underlying storage.
		for offset < len(inserts) {
			candidate := inserts[offset]
			if candidate < entry && candidate > lastKey {
				// Item existed in storage.
				keys = append(keys, candidate)
				offset += 1
				lastKey = candidate
				continue
			}

			if candidate == entry {
				// It doesn't really matter which copy we insert, so skip this
				// one and insert the outer loop's one.
				offset += 1
				break
			}

			// Since our current item isn't yet slated for insert, skip it. We
			// know now that offset will be correct:
			//
			// On first loop iteration, we have an empty keys list and thus it
			// holds that lastKey == "". We then insert any candidates up to
			// entry.
			//
			// If entry is present both in storage and in our candidate list,
			// we increment offset again. Thus it holds that
			// candidate > lastKey is maintained.
			break
		}

		// When this key represents a folder that already exists, we should skip it.
		if isFolder && len(keys) > 0 && lastKey == entry {
			continue
		}

		// Finally, include this entry. It is not present in the list.
		keys = append(keys, entry)
	}

	// Loop exit may occur on context cancellation, so check that rather than
	// returning partial results.
	if listerErr != nil {
		return nil, nil, listerErr
	}

	// Now, merge in any newly-added entries one more time. This handles the
	// case where there were no on-disk entries, or when there were too few and
	// subsequent entries were added here.
	lastKey := ""
	if len(keys) > 0 {
		lastKey = keys[len(keys)-1]
	}
	for offset < len(inserts) {
		candidate := inserts[offset]
		offset += 1

		if candidate > lastKey {
			// Item existed in storage.
			keys = append(keys, candidate)
			continue
		}
	}

	// Trim keys up to our limit; don't go over: the above final update
	// reconciling logic means we might accidentally go over even though
	// the main loop validates the limit.
	actualLimit := len(keys)
	if l.Limit > 0 && l.Limit < actualLimit {
		actualLimit = l.Limit
	}

	return keys[:actualLimit], presentKeys, nil
}
